"""`sett-mcp check <url>`: test a deployed MCP server the way clients will, before you share it.

Works on any MCP server over Streamable HTTP, not only Sett's. Without a token it checks
what every client needs before signing in: HTTPS, the 401 that points to sign-in, the
protected-resource metadata and the authorization server's. With `--token` (or on a
server that needs no sign-in) it also lists the tools and checks what models and clients
read from them. Only the standard library; nothing is changed on the server.
"""

from __future__ import annotations

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
TOOL_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# (method, url, headers, body) -> (status, headers, body)
Request = Callable[[str, str, Mapping[str, str], "bytes | None"], "tuple[int, Mapping[str, str], bytes]"]


@dataclass
class Result:
    status: str  # PASS, WARN, FAIL or INFO
    name: str
    detail: str = ""
    fix: str = ""


def http_request(method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> tuple[int, Mapping[str, str], bytes]:
    request = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310 (the URL being checked)
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
    parts = urlsplit(url)
    loopback = parts.hostname in LOOPBACK
    results: list[Result] = []
    add = results.append

    if parts.scheme == "https":
        add(Result("PASS", "Uses HTTPS"))
    elif loopback:
        add(Result("INFO", "Plain http on this machine", "Fine for testing; deploy with https"))
    else:
        add(Result("FAIL", "Uses plain http", url, "Clients send sign-in tokens to this address; serve it over https"))

    try:
        status, headers, body = _post(request, url, _initialize(), None)
    except (urllib.error.URLError, OSError) as exc:
        add(Result("FAIL", "Server reachable", str(exc), "Check the address, and that the server is running"))
        return results

    session: dict[str, str] = {}
    if status == 401:
        add(Result("PASS", "Requires sign-in", "Requests without a token get 401"))
        _check_sign_in(url, headers, request, add)
        if token:
            status, headers, body = _post(request, url, _initialize(), token)
            if status != 200:
                add(Result("FAIL", "Token accepted", f"HTTP {status}", "The token may be expired, or issued for another server (its audience must be this URL)"))
                return results
            add(Result("PASS", "Token accepted"))
        else:
            _check_get(url, request, None, add)
            add(Result("INFO", "Tools not checked", "Add --token - to check them too (it asks for an access token)"))
            return results
    elif status == 200:
        if loopback:
            add(Result("INFO", "No sign-in required", "Fine on this machine"))
        else:
            add(Result("WARN", "No sign-in required", "Anyone who finds this address can call its tools", "Add sign-in before sharing it (Sett: deploy vercel --auth supabase)"))
    else:
        add(Result("FAIL", "Answers MCP requests", f"POST {parts.path} answered HTTP {status}: {_snippet(body)}", "Is this the MCP endpoint? Most servers answer at /mcp"))
        return results

    message = _message(headers, body)
    info = (message or {}).get("result", {})
    if not info.get("protocolVersion"):
        add(Result("FAIL", "Initialize", _snippet(body), "The server didn't return an MCP initialize result"))
        return results
    server = info.get("serverInfo", {})
    name = " ".join(str(v) for v in (server.get("name"), server.get("version")) if v) or "unnamed server"
    add(Result("PASS", "Initialize", f"{name}, protocol {info['protocolVersion']}"))
    if headers.get("mcp-session-id"):
        session["mcp-session-id"] = headers["mcp-session-id"]
    session["mcp-protocol-version"] = str(info["protocolVersion"])
    _post(request, url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, token, session)

    _check_get(url, request, token, add)
    _check_origin(url, request, token, session, add)
    _check_tools(url, request, token, session, add)
    return results


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
    except (urllib.error.URLError, OSError):
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
    servers = metadata.get("authorization_servers") or []
    if not servers:
        add(Result("FAIL", "Authorization server named", "authorization_servers is empty", "List the issuer clients sign in with"))
        return
    _check_authorization_server(str(servers[0]), request, add)


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
    add(Result("PASS", "Authorization server metadata", issuer))
    if "S256" in (metadata.get("code_challenge_methods_supported") or []):
        add(Result("PASS", "PKCE (S256)"))
    else:
        add(Result("FAIL", "PKCE (S256)", "code_challenge_methods_supported doesn't list S256", "MCP clients require PKCE and may refuse to sign in"))
    if metadata.get("registration_endpoint"):
        add(Result("PASS", "Clients can register themselves", "Dynamic client registration"))
    elif metadata.get("client_id_metadata_document_supported"):
        add(Result("PASS", "Clients can register themselves", "Client ID metadata documents"))
    else:
        add(Result("WARN", "Clients can register themselves", "No registration_endpoint and no client ID metadata documents", "Each client must then be registered by hand; Claude and Cursor expect to register themselves"))


def _check_get(url: str, request: Request, token: str | None, add: Callable[[Result], None]) -> None:
    headers = {"Accept": "text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        status, response, _ = request("GET", url, headers, None)
    except (urllib.error.URLError, OSError) as exc:
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
    status, headers, body = _post(request, url, {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, token, session)
    tools = ((_message(headers, body) or {}).get("result") or {}).get("tools")
    if status != 200 or not isinstance(tools, list):
        add(Result("FAIL", "Lists tools", f"HTTP {status}: {_snippet(body)}"))
        return
    add(Result("PASS", "Lists tools", f"{len(tools)} tool{'s' if len(tools) != 1 else ''}"))
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
        for name, schema in ((t.get("inputSchema") or {}).get("properties") or {}).items()
        if isinstance(schema, dict) and not schema.get("description")
    )
    if undescribed:
        shown = ", ".join(undescribed[:8]) + (f" and {len(undescribed) - 8} more" if len(undescribed) > 8 else "")
        add(Result("WARN", "Parameter descriptions", f"Missing: {shown}", "Describe each parameter: its format, an example, its limits"))
    else:
        add(Result("PASS", "Parameter descriptions"))
    unhinted = [t.get("name") for t in tools if not any(k in (t.get("annotations") or {}) for k in ("readOnlyHint", "destructiveHint"))]
    if unhinted:
        add(Result("WARN", "Read-only and destructive hints", f"None on: {', '.join(map(str, unhinted))}", "Clients use readOnlyHint and destructiveHint to decide when to ask the user first"))
    else:
        add(Result("PASS", "Read-only and destructive hints"))


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
