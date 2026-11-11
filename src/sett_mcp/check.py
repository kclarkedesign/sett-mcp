"""`sett-mcp check <url>`: test a deployed MCP server the way clients will, before you share it.

Works on any MCP server over Streamable HTTP, not only Sett's. Without a token it checks
what every client needs before signing in: HTTPS, the 401 that points to sign-in, the
protected-resource metadata and the authorization server's. With `--token` (or on a
server that needs no sign-in) it also tries both ways clients talk to a server, the
2026-07-28 protocol (server/discover, no session) and the older initialize handshake,
then lists the tools and checks what models and clients read from them. Only the standard library; nothing is changed on the server.
"""

from __future__ import annotations

import http.client
import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

PROTOCOL = "2025-11-25"  # the newest handshake (initialize) version
MODERN = "2026-07-28"  # no handshake: server/discover, then self-contained requests
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
    try:
        request = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": USER_AGENT, **headers})
    except ValueError as exc:  # a relative or otherwise unusable address in the server's metadata
        raise urllib.error.URLError(f"not a usable address: {url}") from exc
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

    modern_era, handshake_era = _Era(modern=True), _Era(modern=False)
    try:  # anonymously, as a client's first request: the current protocol first, then the handshake
        status, headers, body = _call(request, url, None, modern_era, "server/discover", 1)
        if status != 401 and not 300 <= status < 400 and not _discovered(headers, body):
            status, headers, body = _post(request, url, _initialize(), None)
    except TRANSPORT_ERRORS as exc:
        add(Result("FAIL", "Server reachable", str(exc), "Check the address, and that the server is running"))
        return

    if status == 401:
        add(Result("PASS", "Requires sign-in", "Requests without a token get 401"))
        _check_sign_in(url, headers, request, add)
        if not token:
            _check_get(url, request, None, {}, add)
            add(Result("INFO", "Tools not checked", "Add --token - to check them too (it asks for an access token)"))
            return
    elif status == 200:
        pass  # whether sign-in is needed is decided once tools/list has been tried
    elif 300 <= status < 400:
        where = headers.get("location", "somewhere else")
        add(Result("FAIL", "Answers MCP requests", f"POST {parts.path} redirects (HTTP {status}) to {where}", "Give clients the final address: they don't follow redirects with requests and tokens"))
        return
    else:
        add(Result("FAIL", "Answers MCP requests", f"POST {parts.path} answered HTTP {status}: {_snippet(body)}", "Is this the MCP endpoint? Most servers answer at /mcp"))
        return

    # Both protocol eras, with the token if there is one (its own session, so the tools
    # are listed as the token's user sees them).
    m_status, m_headers, m_body = _call(request, url, token, modern_era, "server/discover", 1)
    discovered = _discovered(m_headers, m_body) if m_status == 200 else {}
    modern_ok = bool(discovered)
    h_status, h_headers, h_body = _post(request, url, _initialize(), token)
    info = _dict((_message(h_headers, h_body, 1) or {}).get("result"))
    handshake_ok = h_status == 200 and bool(info.get("protocolVersion"))
    if not token and 401 in (m_status, h_status):  # one of them is public, the other needs sign-in
        _requires_sign_in(url, h_headers if h_status == 401 else m_headers, request, add, "Some requests are public, but this one needs a token")
        return

    if not (modern_ok or handshake_ok):
        if token and {m_status, h_status} & {401, 403}:
            add(Result("FAIL", "Token accepted", f"HTTP {h_status if h_status in (401, 403) else m_status}", "The token may be expired, or issued for another server (its audience must be this URL)"))
        else:
            add(Result("FAIL", "Answers MCP requests", f"server/discover: HTTP {m_status}; initialize: HTTP {h_status}: {_snippet(h_body)}", "The server didn't return an MCP result for either protocol version"))
        return
    if token:
        add(Result("PASS", "Token accepted"))

    if modern_ok:
        add(Result("PASS", f"Protocol {MODERN}", _server_name(_dict(_dict(discovered.get("_meta")).get("io.modelcontextprotocol/serverInfo")))))
    else:
        add(Result("INFO", f"Protocol {MODERN}", "Not offered; current clients fall back to the handshake"))
    if handshake_ok:
        add(Result("PASS", "Handshake protocol", f"{_server_name(_dict(info.get('serverInfo')))}, {info['protocolVersion']}"))
        if h_headers.get("mcp-session-id"):
            handshake_era.headers["mcp-session-id"] = h_headers["mcp-session-id"]
        handshake_era.headers["mcp-protocol-version"] = str(info["protocolVersion"])
        _post(request, url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, token, handshake_era.headers)
    else:
        add(Result("WARN", "Handshake protocol", f"initialize answered HTTP {h_status}", f"Clients that haven't moved to {MODERN} can't connect; serve both (the MCP Python SDK does by default)"))

    era = modern_era if modern_ok else handshake_era  # what current clients use
    get_headers = handshake_era.headers if handshake_ok else {"mcp-protocol-version": MODERN}
    challenge = _check_tools(url, request, token, era, add)
    if challenge is not None:  # discovery is public, the tools aren't: that's sign-in working
        _requires_sign_in(url, challenge, request, add, "Discovery is public; tools/list needs a token")
        return
    if not token:
        if loopback:
            add(Result("INFO", "No sign-in required", "Fine on this machine"))
        else:
            add(Result("WARN", "No sign-in required", "Anyone who finds this address can list and call its tools", "Add sign-in before sharing it (Sett: deploy vercel --auth supabase)"))
    _check_get(url, request, token, get_headers, add)
    _check_origin(url, request, token, era, add)


def _requires_sign_in(url: str, headers: Mapping[str, str], request: Request, add: Callable[[Result], None], detail: str) -> None:
    add(Result("PASS", "Requires sign-in", detail))
    _check_sign_in(url, headers, request, add)
    add(Result("INFO", "Tools not checked", "Add --token - to check them too (it asks for an access token)"))


def _discovered(headers: Mapping[str, str], body: bytes) -> dict[str, Any]:
    """A 2026-07-28 server/discover result offering that version, or {} (an error, or another reply)."""
    result = _dict((_message(headers, body, 1) or {}).get("result"))
    versions = result.get("supportedVersions")
    return result if isinstance(versions, list) and MODERN in versions else {}


@dataclass
class _Era:
    """How requests are framed: 2026-07-28 (self-contained) or the handshake (a session)."""

    modern: bool
    headers: dict[str, str] = field(default_factory=dict)  # the handshake's session headers


def _call(request: Request, url: str, token: str | None, era: _Era, method: str, id_: int, params: Mapping[str, Any] | None = None, headers: Mapping[str, str] | None = None) -> tuple[int, Mapping[str, str], bytes]:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": id_, "method": method}
    params = dict(params or {})
    sent = dict(era.headers)
    if era.modern:  # each request carries the version, the client and its capabilities
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": MODERN,
            "io.modelcontextprotocol/clientInfo": {"name": USER_AGENT, "version": "1"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        sent |= {"mcp-protocol-version": MODERN, "mcp-method": method}
    if params:
        payload["params"] = params
    return _post(request, url, payload, token, sent, headers)


def _server_name(server: Mapping[str, Any]) -> str:
    return " ".join(str(v) for v in (server.get("name"), server.get("version")) if v) or "unnamed server"


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


def _message(headers: Mapping[str, str], body: bytes, id_: int) -> dict[str, Any] | None:
    """The JSON-RPC reply to request `id_`, whether the server answered with JSON or an event stream.

    Replies for another id are ignored, as a client would: it matches replies to requests by id.
    """
    text = body.decode(errors="replace")
    if headers.get("content-type", "").startswith("text/event-stream"):
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    data = json.loads(line[5:].strip())
                except ValueError:
                    continue
                if isinstance(data, dict) and ("result" in data or "error" in data) and data.get("id") == id_:
                    return data
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) and data.get("id") == id_ else None


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
    well_known = f"{parts.scheme}://{parts.netloc}/.well-known/oauth-protected-resource{parts.path}"
    metadata_url = found.group(1) if found else well_known
    if found and not _usable(metadata_url):
        add(Result("FAIL", "401 points to sign-in", f"resource_metadata is {metadata_url}, not an https address", "Send the full https address of the resource metadata; clients won't fetch it otherwise"))
        metadata_url = well_known
    elif found:
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
    if not _usable(issuer):
        add(Result("FAIL", "Authorization server metadata", f"The issuer {issuer} isn't an https address", "List the issuer's full https address in authorization_servers"))
        return
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


def _check_get(url: str, request: Request, token: str | None, session: Mapping[str, str], add: Callable[[Result], None]) -> None:
    headers = {"Accept": "text/event-stream", **session}
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


def _check_origin(url: str, request: Request, token: str | None, era: _Era, add: Callable[[Result], None]) -> None:
    method = "server/discover" if era.modern else "ping"  # 2026-07-28 has no ping
    status, _, _ = _call(request, url, token, era, method, 2, headers={"Origin": "https://example.invalid"})
    if status == 403:
        add(Result("PASS", "Refuses other websites", "A request from another site's page gets 403"))
    else:
        add(Result("WARN", "Refuses other websites", f"A request with Origin: https://example.invalid got HTTP {status}", "Check the Origin header, so another website's page can't call the server through a visitor's browser"))


def _check_tools(url: str, request: Request, token: str | None, era: _Era, add: Callable[[Result], None]) -> Mapping[str, str] | None:
    """Check the tools; returns the 401's headers when listing them needs a token we don't have."""
    tools: list[Any] = []
    cursor = None
    for page in range(MAX_PAGES):
        params = {"cursor": cursor} if cursor else {}
        status, headers, body = _call(request, url, token, era, "tools/list", 3 + page, params)
        if status == 401 and not token and page == 0:
            return headers
        result = _dict((_message(headers, body, 3 + page) or {}).get("result"))
        if status != 200 or not isinstance(result.get("tools"), list):
            add(Result("FAIL", "Lists tools", f"HTTP {status}: {_snippet(body)}" + (f" (page {page + 1})" if page else "")))
            return None
        tools += result["tools"]
        cursor = result.get("nextCursor")
        if not cursor:
            break
    else:
        add(Result("WARN", "Lists tools", f"Stopped after {MAX_PAGES} pages; only those tools were checked", "A nextCursor that never runs out makes clients loop too"))
    add(Result("PASS", "Lists tools", f"{len(tools)} tool{'s' if len(tools) != 1 else ''}"))
    malformed = [_label(t, i) for i, t in enumerate(tools) if _schema_problem(t)]
    if malformed:
        add(Result("FAIL", "Tool definitions", f"Malformed: {', '.join(malformed)}", "Each tool needs an inputSchema with \"type\": \"object\" (and properties, if any, as an object); clients may drop or reject these tools"))
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
    return None


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _schema_problem(tool: object) -> bool:
    """True when a tool entry isn't an object, or its inputSchema doesn't describe one."""
    if not isinstance(tool, dict):
        return True
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return True
    return not isinstance(schema.get("properties", {}), dict) or not isinstance(tool.get("annotations", {}), dict)


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
