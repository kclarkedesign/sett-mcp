"""`sett-mcp check <url>`: test a deployed MCP server the way clients will, before you share it.

Works on any MCP server over Streamable HTTP, not only Sett's. Without a token it checks
what every client needs before signing in: HTTPS, the 401 that points to sign-in, the
protected-resource metadata and the authorization server's. With `--token` (or on a
server that needs no sign-in) it also lists the tools and checks what models and clients
read from them. Only the standard library; nothing is changed on the server.
"""

from __future__ import annotations

import http.client
import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

PROTOCOL = "2025-11-25"
USER_AGENT = "sett-mcp-check"
LOOPBACK = {"localhost", "127.0.0.1", "::1"}
# What a dropped, reset or timed-out connection raises.
TRANSPORT_ERRORS = (urllib.error.URLError, OSError, http.client.HTTPException)
MAX_PAGES = 50  # of tools/list
TOOL_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# (method, url, headers, body) -> (status, headers, body)
Request = Callable[[str, str, Mapping[str, str], "bytes | None"], "tuple[int, Mapping[str, str], bytes]"]


@dataclass
class Result:
    status: str  # PASS, WARN, FAIL or INFO
    name: str
    detail: str = ""
    fix: str = ""


def _origin(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return parts.scheme.lower(), parts.netloc.lower()


class _SafeRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only when it can't leak the token or change what's being checked.

    A POST isn't followed at all (the 3xx is reported instead), a redirect from https to
    http isn't followed, and a request carrying a token is only followed on the same origin:
    urllib would otherwise copy the Authorization header to wherever the server points.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if req.get_method() == "POST":
            return None
        old, new = _origin(req.full_url), _origin(newurl)
        if old[0] == "https" and new[0] != "https":
            return None
        if new != old and (req.has_header("Authorization") or "Authorization" in req.unredirected_hdrs):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_SafeRedirects)


def http_request(method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> tuple[int, Mapping[str, str], bytes]:
    request = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": USER_AGENT, **headers})
    try:
        with _opener.open(request, timeout=15) as response:  # the URL being checked
            # A GET may open an event stream that never ends: read the headers, not the body.
            raw = b"" if response.headers.get("content-type", "").startswith("text/event-stream") and method == "GET" else response.read()
            return response.status, {k.lower(): v for k, v in response.headers.items()}, raw
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def normalize(url: str) -> str:
    """The MCP endpoint: `/mcp` is added when only a host is given."""
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    path = parts.path if parts.path not in ("", "/") else "/mcp"
    return urlunsplit((parts.scheme, parts.netloc.lower(), path.rstrip("/") or "/mcp", parts.query, ""))


def check(url: str, *, token: str | None = None, request: Request = http_request) -> list[Result]:
    url = normalize(url)
    results: list[Result] = []
    try:
        _check(url, token, request, results.append)
    except TRANSPORT_ERRORS as exc:  # after the first answer: report what was found so far
        results.append(Result("FAIL", "Connection", f"Lost partway through the checks: {exc}", "Run the check again; if it keeps happening, the server's logs say why"))
    return results


def _check(url: str, token: str | None, request: Request, add: Callable[[Result], None]) -> None:
    parts = urlsplit(url)
    loopback = parts.hostname in LOOPBACK

    if parts.scheme == "https":
        add(Result("PASS", "Uses HTTPS"))
    elif loopback:
        add(Result("INFO", "Plain http on this machine", "Fine for testing; deploy with https"))
    else:
        add(Result("FAIL", "Uses plain http", url, "Clients send sign-in tokens to this address; serve it over https"))
        if token:  # never put a credential on the network unencrypted, even to check it
            add(Result("FAIL", "Token not sent", "This address is plain http, so the token would cross the network unencrypted", "Check the https address instead"))
            token = None

    try:
        status, headers, body = _post(request, url, _initialize(), None)
    except TRANSPORT_ERRORS as exc:
        add(Result("FAIL", "Server reachable", str(exc), "Check the address, and that the server is running"))
        return

    session: dict[str, str] = {}
    if status == 401:
        add(Result("PASS", "Requires sign-in", "Requests without a token get 401"))
        _check_sign_in(url, headers, request, add)
        if not token:
            _check_get(url, request, None, add)
            add(Result("INFO", "Tools not checked", "Add --token - to check them too (it asks for an access token)"))
            return
    elif status == 200:
        if loopback:
            add(Result("INFO", "No sign-in required", "Fine on this machine"))
        else:
            add(Result("WARN", "No sign-in required", "Anyone who finds this address can call its tools", "Add sign-in before sharing it (Sett: deploy vercel --auth supabase)"))
    elif 300 <= status < 400:
        where = headers.get("location", "somewhere else")
        add(Result("FAIL", "Answers MCP requests", f"POST {parts.path} redirects (HTTP {status}) to {where}", "Give clients the final address: they don't follow redirects with requests and tokens"))
        return
    else:
        add(Result("FAIL", "Answers MCP requests", f"POST {parts.path} answered HTTP {status}: {_snippet(body)}", "Is this the MCP endpoint? Most servers answer at /mcp"))
        return

    if token:  # a session of its own, so the tools are listed as the token's user sees them
        status, headers, body = _post(request, url, _initialize(), token)
        if status != 200:
            add(Result("FAIL", "Token accepted", f"HTTP {status}", "The token may be expired, or issued for another server (its audience must be this URL)"))
            return
        add(Result("PASS", "Token accepted"))

    info = _dict((_message(headers, body) or {}).get("result"))
    if not info.get("protocolVersion"):
        add(Result("FAIL", "Initialize", _snippet(body), "The server didn't return an MCP initialize result"))
        return
    server = _dict(info.get("serverInfo"))
    name = " ".join(str(v) for v in (server.get("name"), server.get("version")) if v) or "unnamed server"
    add(Result("PASS", "Initialize", f"{name}, protocol {info['protocolVersion']}"))
    if headers.get("mcp-session-id"):
        session["mcp-session-id"] = headers["mcp-session-id"]
    session["mcp-protocol-version"] = str(info["protocolVersion"])
    _post(request, url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, token, session)

    _check_get(url, request, token, add)
    _check_origin(url, request, token, session, add)
    _check_tools(url, request, token, session, add)
    return


def _initialize() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": USER_AGENT, "version": "1"}},
    }


def _post(request: Request, url: str, payload: dict[str, Any], token: str | None, extra: Mapping[str, str] | None = None, headers: Mapping[str, str] | None = None) -> tuple[int, Mapping[str, str], bytes]:
    sent = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", **(extra or {}), **(headers or {})}
    if token:
        sent["Authorization"] = f"Bearer {token}"
    return request("POST", url, sent, json.dumps(payload).encode())


def _message(headers: Mapping[str, str], body: bytes) -> dict[str, Any] | None:
    """The JSON-RPC reply, whether the server answered with JSON or an event stream."""
    text = body.decode(errors="replace")
    if headers.get("content-type", "").startswith("text/event-stream"):
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    data = json.loads(line[5:].strip())
                except ValueError:
                    continue
                if isinstance(data, dict) and ("result" in data or "error" in data):
                    return data
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _snippet(body: bytes) -> str:
    return body.decode(errors="replace").strip().replace("\n", " ")[:160]


def _json(request: Request, url: str) -> dict[str, Any] | None:
    try:
        status, _, body = request("GET", url, {"Accept": "application/json"}, None)
    except TRANSPORT_ERRORS:
        return None
    if status != 200:
        return None
    try:
        data = json.loads(body)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _check_sign_in(url: str, headers: Mapping[str, str], request: Request, add: Callable[[Result], None]) -> None:
    challenge = headers.get("www-authenticate", "")
    found = re.search(r'resource_metadata="([^"]+)"', challenge)
    parts = urlsplit(url)
    metadata_url = found.group(1) if found else f"{parts.scheme}://{parts.netloc}/.well-known/oauth-protected-resource{parts.path}"
    if found:
        add(Result("PASS", "401 points to sign-in", "WWW-Authenticate names the resource metadata"))
    else:
        add(Result("WARN", "401 points to sign-in", "No resource_metadata in WWW-Authenticate", "Clients fall back to the well-known address; send resource_metadata in the challenge (RFC 9728)"))

    metadata = _json(request, metadata_url)
    if metadata is None:
        add(Result("FAIL", "Protected resource metadata", f"Nothing usable at {metadata_url}", "Serve RFC 9728 metadata there, naming this URL and its authorization server"))
        return
    resource = str(metadata.get("resource", "")).rstrip("/")
    if resource == url.rstrip("/"):
        add(Result("PASS", "Protected resource metadata", f"resource = {resource}"))
    else:
        add(Result("FAIL", "Protected resource metadata", f"resource is {resource or 'missing'}, but clients connect to {url}", "Tokens are issued for the resource URL; it must be the address clients use (Sett: <PREFIX>_PUBLIC_URL)"))
    servers = metadata.get("authorization_servers")
    if not isinstance(servers, list) or not servers or not isinstance(servers[0], str):
        add(Result("FAIL", "Authorization server named", "authorization_servers is missing, empty or not a list of addresses", "List the issuer clients sign in with"))
        return
    _check_authorization_server(servers[0], request, add)


def _check_authorization_server(issuer: str, request: Request, add: Callable[[Result], None]) -> None:
    parts = urlsplit(issuer)
    base, path = f"{parts.scheme}://{parts.netloc}", parts.path.rstrip("/")
    candidates = [  # RFC 8414 puts the well-known part before the issuer's path; OpenID after it
        f"{base}/.well-known/oauth-authorization-server{path}",
        f"{base}/.well-known/openid-configuration{path}",
        f"{base}{path}/.well-known/openid-configuration",
        f"{base}{path}/.well-known/oauth-authorization-server",
    ]
    metadata = next((m for m in (_json(request, c) for c in dict.fromkeys(candidates)) if m), None)
    if metadata is None:
        add(Result("FAIL", "Authorization server metadata", f"None found for {issuer}", "Clients read it to find where to sign in"))
        return
    problems = []
    named = str(metadata.get("issuer") or "")
    if named.rstrip("/") != issuer.rstrip("/"):
        problems.append(f"issuer is {named or 'missing'}, expected {issuer}")
    for key in ("authorization_endpoint", "token_endpoint"):
        if not _usable(metadata.get(key)):
            problems.append(f"{key} is {metadata.get(key) or 'missing'}, not an https address")
    if problems:
        add(Result("FAIL", "Authorization server metadata", "; ".join(problems), "Clients check these before signing in, and stop if they're wrong (RFC 8414)"))
    elif named != issuer:
        add(Result("WARN", "Authorization server metadata", f"issuer {named} and {issuer} differ by a trailing slash", "Strict clients compare them exactly; make them identical"))
    else:
        add(Result("PASS", "Authorization server metadata", issuer))
    methods = metadata.get("code_challenge_methods_supported")
    if isinstance(methods, list) and "S256" in methods:
        add(Result("PASS", "PKCE (S256)"))
    else:
        add(Result("FAIL", "PKCE (S256)", "code_challenge_methods_supported doesn't list S256", "MCP clients require PKCE and may refuse to sign in"))
    if _usable(metadata.get("registration_endpoint")):
        add(Result("PASS", "Clients can register themselves", "Dynamic client registration"))
    elif metadata.get("client_id_metadata_document_supported"):
        add(Result("PASS", "Clients can register themselves", "Client ID metadata documents"))
    else:
        add(Result("WARN", "Clients can register themselves", "No registration_endpoint and no client ID metadata documents", "Each client must then be registered by hand; Claude and Cursor expect to register themselves"))


def _usable(endpoint: object) -> bool:
    """An absolute https address (plain http only on this machine)."""
    if not isinstance(endpoint, str):
        return False
    parts = urlsplit(endpoint)
    return bool(parts.netloc) and (parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in LOOPBACK))


def _check_get(url: str, request: Request, token: str | None, add: Callable[[Result], None]) -> None:
    headers = {"Accept": "text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        status, response, _ = request("GET", url, headers, None)
    except TRANSPORT_ERRORS as exc:
        add(Result("WARN", "GET on the endpoint", f"No answer ({exc})", "Answer GET with 405, or with an event stream, so clients don't wait"))
        return
    if status == 405:
        add(Result("PASS", "GET on the endpoint", "405, so clients don't hold a stream open"))
    elif status == 200 and response.get("content-type", "").startswith("text/event-stream"):
        add(Result("PASS", "GET on the endpoint", "Opens an event stream"))
    elif status == 401 and not token:
        add(Result("PASS", "GET on the endpoint", "Requires sign-in too"))
    else:
        add(Result("WARN", "GET on the endpoint", f"HTTP {status}", "Answer GET with 405 or an event stream"))


def _check_origin(url: str, request: Request, token: str | None, session: Mapping[str, str], add: Callable[[Result], None]) -> None:
    ping = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
    status, _, _ = _post(request, url, ping, token, session, {"Origin": "https://example.invalid"})
    if status == 403:
        add(Result("PASS", "Refuses other websites", "A request from another site's page gets 403"))
    else:
        add(Result("WARN", "Refuses other websites", f"A request with Origin: https://example.invalid got HTTP {status}", "Check the Origin header, so another website's page can't call the server through a visitor's browser"))


def _check_tools(url: str, request: Request, token: str | None, session: Mapping[str, str], add: Callable[[Result], None]) -> None:
    tools: list[Any] = []
    cursor = None
    for page in range(MAX_PAGES):
        params = {"cursor": cursor} if cursor else {}
        status, headers, body = _post(request, url, {"jsonrpc": "2.0", "id": 3 + page, "method": "tools/list", "params": params}, token, session)
        result = _dict((_message(headers, body) or {}).get("result"))
        if status != 200 or not isinstance(result.get("tools"), list):
            add(Result("FAIL", "Lists tools", f"HTTP {status}: {_snippet(body)}" + (f" (page {page + 1})" if page else "")))
            return
        tools += result["tools"]
        cursor = result.get("nextCursor")
        if not cursor:
            break
    else:
        add(Result("WARN", "Lists tools", f"Stopped after {MAX_PAGES} pages; only those tools were checked", "A nextCursor that never runs out makes clients loop too"))
    add(Result("PASS", "Lists tools", f"{len(tools)} tool{'s' if len(tools) != 1 else ''}"))
    malformed = [_label(t, i) for i, t in enumerate(tools) if _schema_problem(t)]
    if malformed:
        add(Result("FAIL", "Tool definitions", f"Malformed: {', '.join(malformed)}", "Each tool needs an object inputSchema whose properties is an object; clients may drop or reject these tools"))
    tools = [t for t in tools if not _schema_problem(t)]
    bad_names = [t.get("name") for t in tools if not TOOL_NAME.match(str(t.get("name", "")))]
    if bad_names:
        add(Result("FAIL", "Tool names", ", ".join(map(str, bad_names)), "Use 1-64 letters, digits, _ or -; some clients reject other names"))
    thin = [t.get("name") for t in tools if len(str(t.get("description") or "").strip()) < 20]
    if thin:
        add(Result("WARN", "Tool descriptions", f"Missing or very short: {', '.join(map(str, thin))}", "The model chooses tools by their description: say what it does and when to use it"))
    else:
        add(Result("PASS", "Tool descriptions"))
    undescribed = sorted(
        f"{t.get('name')}.{name}"
        for t in tools
        for name, schema in (t["inputSchema"].get("properties") or {}).items()
        if isinstance(schema, dict) and not schema.get("description")
    )
    if undescribed:
        shown = ", ".join(undescribed[:8]) + (f" and {len(undescribed) - 8} more" if len(undescribed) > 8 else "")
        add(Result("WARN", "Parameter descriptions", f"Missing: {shown}", "Describe each parameter: its format, an example, its limits"))
    else:
        add(Result("PASS", "Parameter descriptions"))
    unhinted = [t.get("name") for t in tools if not any(k in _dict(t.get("annotations")) for k in ("readOnlyHint", "destructiveHint"))]
    if unhinted:
        add(Result("WARN", "Read-only and destructive hints", f"None on: {', '.join(map(str, unhinted))}", "Clients use readOnlyHint and destructiveHint to decide when to ask the user first"))
    else:
        add(Result("PASS", "Read-only and destructive hints"))


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _schema_problem(tool: object) -> bool:
    """True when a tool entry isn't an object, or its inputSchema or properties isn't one."""
    if not isinstance(tool, dict):
        return True
    schema = tool.get("inputSchema")
    return not isinstance(schema, dict) or not isinstance(schema.get("properties", {}), dict) or not isinstance(tool.get("annotations", {}), dict)


def _label(tool: object, index: int) -> str:
    name = tool.get("name") if isinstance(tool, dict) else None
    return str(name) if name else f"tool #{index + 1}"


def report(results: list[Result], say: Callable[[str], None] = print) -> int:
    """Print the results; the exit code is 1 when anything failed."""
    width = max((len(r.name) for r in results), default=0)
    for r in results:
        line = f"{r.status:<4}  {r.name:<{width}}"
        if r.detail:
            line += f"  {r.detail}"
        say(line.rstrip())
        if r.fix and r.status in ("FAIL", "WARN"):
            say(f"{'':<6}{'':<{width}}  -> {r.fix}")
    failed = sum(r.status == "FAIL" for r in results)
    warned = sum(r.status == "WARN" for r in results)
    say("")
    passed = sum(r.status == "PASS" for r in results)
    summary = f"{failed} failed, {warned} warning{'s' if warned != 1 else ''}, {passed} passed." if failed or warned else f"All {passed} checks passed."
    say(summary)
    return 1 if failed else 0
