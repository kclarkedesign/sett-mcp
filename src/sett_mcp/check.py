"""`sett-mcp check <url>`: test a deployed MCP server the way clients will, before you share it.

Works on any MCP server over Streamable HTTP, not only Sett's. Without a token it checks
what every client needs before signing in: HTTPS, the 401 that points to sign-in, the
protected-resource metadata and the authorization server's, looked up in the order the
MCP Python SDK's client uses. With `--token` (or on a server that needs no sign-in) it
also tries both ways clients talk to a server, the 2026-07-28 protocol (server/discover,
no session) and the older initialize handshake, then lists the tools and checks what
models and clients read from them.

Only the standard library. Nothing is changed on the server, the token is only sent to
the address being checked (never over plain http to another machine, never through a
redirect to another origin), and a broken server is reported, never a traceback.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

MODERN = "2026-07-28"  # no handshake: server/discover, then self-contained requests
HANDSHAKE_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")  # via initialize
PROTOCOL = HANDSHAKE_VERSIONS[-1]  # what this check offers in initialize
USER_AGENT = "sett-mcp-check"
LOOPBACK = {"localhost", "127.0.0.1", "::1"}
DEADLINE = 30.0  # seconds for one whole request, however the server drips or holds it open
MAX_BODY = 10 * 1024 * 1024  # bytes read from any one reply
MAX_PAGES = 50  # of tools/list
FINAL_URL = "x-sett-final-url"  # added to a reply's headers when a redirect was followed
HEADER_SAFE = re.compile(r"[\x21-\x7e]+")  # visible ASCII: what may go in a header value
TOOL_NAME = re.compile(r"[A-Za-z0-9._-]{1,128}")  # the spec's rule
STRICT_TOOL_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")  # what some clients, Claude among them, accept

# What a dropped, reset, timed-out or unusable connection raises.
TRANSPORT_ERRORS = (urllib.error.URLError, OSError, http.client.HTTPException)
NOT_CHECKED = "Add --token - to check them too (it asks for an access token issued for this server)"

# (method, url, headers, body) -> (status, headers, body)
Request = Callable[[str, str, Mapping[str, str], "bytes | None"], "tuple[int, Mapping[str, str], bytes]"]


@dataclass
class Result:
    status: str  # PASS, WARN, FAIL or INFO
    name: str
    detail: str = ""
    fix: str = ""


# --- Transport ------------------------------------------------------------------------


def _origin(url: str) -> tuple[str, str, int | None] | None:
    """(scheme, host, port) with the default port as None, or None for an unusable address."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if port == {"http": 80, "https": 443}.get(scheme):
        port = None
    return scheme, (parts.hostname or "").lower(), port


def within_origin(sent: str, location: str) -> bool:
    """A redirect the MCP SDK's client follows: same origin, or http to https on the same host."""
    old, new = _origin(sent), _origin(location)
    if old is None or new is None or not new[1]:
        return False
    if old == new:
        return True
    return old[1] == new[1] and old[0] == "http" and new[0] == "https" and old[2] is None and new[2] is None


class _SafeRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only where the MCP SDK's client would, so nothing leaks or misleads.

    That is within the origin (or http to https on the same host), and for a POST only a
    307 or 308, which keep the method and body. urllib would otherwise copy the
    Authorization header to wherever the server points, and turn a POST into a GET.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not within_origin(req.full_url, newurl):
            return None
        if req.get_method() == "POST":
            if code not in (307, 308):
                return None
            sent = {**req.headers, **req.unredirected_hdrs}
            return urllib.request.Request(newurl, data=req.data, headers=sent, method="POST")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

    def http_error_302(self, req, fp, code, msg, headers):
        try:  # urllib parses the Location before redirect_request sees it
            return super().http_error_302(req, fp, code, msg, headers)
        except ValueError:  # an unusable Location: report the redirect itself
            return None

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


_opener = urllib.request.build_opener(_SafeRedirects)
_direct = urllib.request.build_opener(_SafeRedirects, urllib.request.ProxyHandler({}))  # no proxy on this machine


def http_request(method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> tuple[int, Mapping[str, str], bytes]:
    """One request, finished within DEADLINE seconds whatever the server does."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["reply"] = _request(method, url, headers, body)
        except BaseException as exc:  # noqa: BLE001 (handed back to the caller below)
            box["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(DEADLINE)
    if worker.is_alive():
        raise TimeoutError(f"no complete answer within {DEADLINE:.0f} seconds")
    if "error" in box:
        error = box["error"]
        if isinstance(error, ValueError):  # an unusable address or header value, e.g. from metadata
            raise urllib.error.URLError(f"not a usable request ({error.__class__.__name__})") from error
        raise error
    return box["reply"]


def _request(method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> tuple[int, Mapping[str, str], bytes]:
    request = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": USER_AGENT, **headers})
    origin = _origin(url)
    opener = _direct if origin and origin[1] in LOOPBACK else _opener
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, _headers(exc.headers), _read(exc)
        finally:
            exc.close()
    with response:
        found = _headers(response.headers)
        if response.geturl() != url:
            found[FINAL_URL] = response.geturl()
        if found.get("content-type", "").lower().startswith("text/event-stream"):
            # A stream may never end: a GET is judged on its headers alone, and a POST is read
            # only until the reply to its request arrives, as a client would.
            return response.status, found, b"" if method == "GET" else _read_events(response, _request_id(body))
        return response.status, found, _read(response)


def _headers(raw: Any) -> dict[str, str]:
    """Lower-cased headers; a repeated one (two WWW-Authenticate, say) keeps every value."""
    found: dict[str, str] = {}
    for key in dict.fromkeys(k.lower() for k in raw):
        found[key] = ", ".join(raw.get_all(key) or [])
    return found


def _read(response: Any) -> bytes:
    chunks, size = [], 0
    while size < MAX_BODY:
        chunk = response.read1(65536) if hasattr(response, "read1") else response.read(65536)
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)[:MAX_BODY]


def _request_id(body: bytes | None) -> object:
    try:
        return json.loads(body or b"null").get("id")
    except (ValueError, AttributeError):
        return None


def _read_events(response: Any, id_: object) -> bytes:
    """An event stream up to and including the event that answers request `id_`."""
    kept: list[bytes] = []
    data: list[str] = []
    size = 0
    while size < MAX_BODY:
        line = response.readline(65536)
        if not line:
            break
        kept.append(line)
        size += len(line)
        text = line.decode(errors="replace").rstrip("\r\n")
        if text.startswith("data:"):
            data.append(text[5:].removeprefix(" "))
        elif not text and data:
            message = _json_object("\n".join(data))
            data = []
            if _is_reply(message, id_):
                break
    return b"".join(kept)


def _transport_fix(exc: BaseException) -> str:
    reason = getattr(exc, "reason", exc)
    if isinstance(exc, TimeoutError) or isinstance(reason, TimeoutError):
        return "The server didn't finish answering. A reply held open (an event stream that never sends the answer) makes clients wait too"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "The server's certificate isn't trusted: it may be expired, self-signed or for another name"
    if isinstance(reason, ssl.SSLError):
        return "The secure connection failed; check the server's https setup"
    return "Check the address, and that the server is running"


def normalize(url: str) -> str:
    """The address to check, as given; `/mcp` is added only when no path was given at all."""
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/mcp", parts.query, ""))


# --- The check ------------------------------------------------------------------------


def check(url: str, *, token: str | None = None, request: Request = http_request) -> list[Result]:
    results: list[Result] = []
    secret = (token or "").strip().removeprefix("Bearer ").strip() or None
    try:
        url = normalize(url)
        _check(url, secret, request, results.append)
    except ValueError:  # an address that can't be parsed at all
        results.append(Result("FAIL", "Address", f"{url} isn't a usable address", "Give the server's full address, e.g. https://my-server.vercel.app/mcp"))
    except TRANSPORT_ERRORS as exc:  # after the first answer: report what was found so far
        results.append(Result("FAIL", "Connection", f"Lost partway through the checks: {exc}", _transport_fix(exc)))
    if secret:  # never print the token, whatever the server echoed back
        for r in results:
            r.detail, r.fix = r.detail.replace(secret, "[token]"), r.fix.replace(secret, "[token]")
    return results


def _check(url: str, token: str | None, request: Request, add: Callable[[Result], None]) -> None:
    parts = urlsplit(url)
    loopback = parts.hostname in LOOPBACK
    add(Result("INFO", "Checking", url))
    not_checked = NOT_CHECKED

    if parts.scheme == "https":
        add(Result("PASS", "Uses HTTPS"))
    elif loopback:
        add(Result("INFO", "Plain http on this machine", "Fine for testing; deploy with https"))
    else:
        add(Result("FAIL", "Uses plain http", url, "Clients send sign-in tokens to this address; serve it over https"))
        if token:  # never put a credential on the network unencrypted, even to check it
            add(Result("FAIL", "Token not sent", "This address is plain http, so the token would cross the network unencrypted", "Check the https address instead"))
            token = None
            not_checked = "Check the https address with --token - to check them too"
    if token and not HEADER_SAFE.fullmatch(token):
        add(Result("FAIL", "Token not sent", "It contains spaces, line breaks or characters a header can't carry", "Copy the token again, without quotes or line breaks"))
        token = None
        not_checked = "Check again with a clean token to check them too"

    modern_era, handshake_era = _Era(modern=True), _Era(modern=False)
    try:  # anonymously, as a client's first request: the current protocol first, then the handshake
        status, headers, body = _call(request, url, None, modern_era, "server/discover", 1)
        if status == 401:  # 2026-07-28 asks for a token; is the handshake public?
            h_status, h_headers, h_body = _post(request, url, _initialize(), None)
            info = _dict((_message(h_headers, h_body, 1) or {}).get("result"))
            if h_status == 200 and info:  # it is: the tools decide, below
                status, headers, body = h_status, h_headers, h_body
        elif not 300 <= status < 400 and not _discovered(headers, body):
            status, headers, body = _post(request, url, _initialize(), None)
    except TRANSPORT_ERRORS as exc:
        add(Result("FAIL", "Server reachable", str(exc), _transport_fix(exc)))
        return
    if headers.get(FINAL_URL):
        add(Result("INFO", "Redirect", f"{url} redirects to {headers[FINAL_URL]}", f"Clients follow it, but giving them {headers[FINAL_URL]} saves a round trip"))

    if status == 401:
        add(Result("PASS", "Requires sign-in", "Requests without a token get 401"))
        _check_sign_in(url, headers, request, add)
        if not token:
            _check_get(url, request, None, {}, add)
            add(Result("INFO", "Tools not checked", not_checked))
            return
    elif 300 <= status < 400:
        where = headers.get("location", "somewhere else")
        add(Result("FAIL", "Answers MCP requests", f"POST {parts.path} redirects (HTTP {status}) to {where}", "Clients only follow a 307 or 308 that stays on this site; give them the final address"))
        return
    elif status != 200:
        add(Result("FAIL", "Answers MCP requests", f"POST {parts.path} answered {_why(status, headers, body)}", "Is this the MCP endpoint? Most servers answer at /mcp"))
        return
    open_first = status == 200  # whether sign-in is needed is decided once tools/list has been tried
    signed_in_checked = status == 401

    # Both protocol eras, with the token if there is one (its own session, so the tools are
    # listed as the token's user sees them).
    m_status, m_headers, m_body = _call(request, url, token, modern_era, "server/discover", 1)
    discovered = _discovered(m_headers, m_body) if m_status == 200 else {}
    modern_problems = _missing_2026_fields(discovered, discover=True) if discovered else []
    modern_ok = bool(discovered) and not modern_problems
    h_status, h_headers, h_body = _post(request, url, _initialize(), token)
    info = _dict((_message(h_headers, h_body, 1) or {}).get("result"))
    handshake_problems = _handshake_problems(info, h_headers) if info else []
    handshake_ok = h_status == 200 and bool(info) and not handshake_problems

    if not token and 401 in (m_status, h_status) and not (modern_ok or handshake_ok):
        _requires_sign_in(url, h_headers if h_status == 401 else m_headers, request, add, "Some requests are public, but this one needs a token", not_checked)
        return
    if not (modern_ok or handshake_ok or discovered or info):
        if token and {m_status, h_status} & {401, 403}:
            rejected = h_headers if h_status in (401, 403) else m_headers
            _token_rejected(url, h_status if h_status in (401, 403) else m_status, rejected, request, add, check_sign_in=not signed_in_checked)
        else:
            add(Result("FAIL", "Answers MCP requests", f"server/discover: {_why(m_status, m_headers, m_body)}; initialize: {_why(h_status, h_headers, h_body)}", "The server didn't return an MCP result for either protocol version"))
        return

    if not token and m_status == 401:
        add(Result("INFO", f"Protocol {MODERN}", "Asks for a token; the handshake doesn't, so its tools decide"))
    elif modern_ok:
        add(Result("PASS", f"Protocol {MODERN}", _server_name(_dict(_dict(discovered.get("_meta")).get("io.modelcontextprotocol/serverInfo")))))
    elif discovered:
        add(Result("FAIL", f"Protocol {MODERN}", f"server/discover is missing or has wrong {', '.join(modern_problems)}", f"Current clients choose {MODERN} and then reject this reply; update the server's MCP SDK"))
    else:
        add(Result("INFO", f"Protocol {MODERN}", "Not offered; current clients fall back to the handshake"))
    if handshake_ok:
        add(Result("PASS", "Handshake protocol", f"{_server_name(_dict(info.get('serverInfo')))}, {info['protocolVersion']}"))
        if h_headers.get("mcp-session-id"):
            handshake_era.headers["mcp-session-id"] = h_headers["mcp-session-id"]
        handshake_era.headers["mcp-protocol-version"] = str(info["protocolVersion"])
        _post(request, url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, token, handshake_era.headers)
    elif info:
        add(Result("FAIL", "Handshake protocol", "; ".join(handshake_problems), "Clients on the handshake reject this initialize result"))
    elif not token and h_status == 401:
        add(Result("INFO", "Handshake protocol", f"Asks for a token; {MODERN} doesn't, so its tools decide"))
    else:
        add(Result("WARN", "Handshake protocol", f"initialize answered {_why(h_status, h_headers, h_body)}", f"Clients that haven't moved to {MODERN} can't connect; serve both (the MCP Python SDK does by default)"))
    if not (modern_ok or handshake_ok):
        return

    era = modern_era if modern_ok else handshake_era  # what current clients use
    get_headers = handshake_era.headers if handshake_ok else {"mcp-protocol-version": MODERN}
    tools_status, tools_headers = _check_tools(url, request, token, era, add, strict=handshake_ok)
    if tools_status in (401, 403):
        if token:  # the token was turned down where it matters
            _token_rejected(url, tools_status, tools_headers, request, add, check_sign_in=not signed_in_checked)
        else:  # discovery is public, the tools aren't: that's sign-in working
            _requires_sign_in(url, tools_headers, request, add, "Discovery is public; tools/list needs a token", not_checked)
        return
    if tools_status == 200 and modern_ok and handshake_ok:
        problem = _handshake_tools(url, request, token, handshake_era)
        if problem:
            add(Result("FAIL", "Tools over the handshake", problem, f"Clients still on the handshake can't use the tools, though {MODERN} clients can"))
    if tools_status == 200:
        if token and open_first:
            _check_open_with_token(url, request, modern_ok, handshake_ok, loopback, add)
        elif token:
            add(Result("PASS", "Token accepted", "tools/list answered with it"))
        elif loopback:
            add(Result("INFO", "No sign-in required", "Fine on this machine"))
        else:
            add(Result("WARN", "No sign-in required", "Anyone who finds this address can list and call its tools", "Add sign-in before sharing it (Sett: deploy vercel --auth supabase)"))
    _check_get(url, request, token, get_headers, add)
    _check_origin(url, request, token, era, add)


def _handshake_tools(url: str, request: Request, token: str | None, era: _Era) -> str:
    """Why tools/list over the handshake session fails, or "" when it works."""
    tools: list[Any] = []
    cursor = None
    for page in range(MAX_PAGES):
        status, headers, body = _call(request, url, token, era, "tools/list", 60 + page, {"cursor": cursor} if cursor else {})
        result = _dict((_message(headers, body, 60 + page) or {}).get("result"))
        if status != 200 or not isinstance(result.get("tools"), list):
            return _why(status, headers, body)
        tools += result["tools"]
        cursor = result.get("nextCursor")
        if cursor is not None and not isinstance(cursor, str):
            return "nextCursor isn't text"
        if not cursor:
            break
    else:
        return f"nextCursor still set after {MAX_PAGES} pages, so clients would keep asking"
    malformed = [f"{_label(t, i)} ({problem})" for i, t in enumerate(tools) if (problem := _tool_problem(t, strict=True))]
    return f"Malformed: {'; '.join(malformed)}" if malformed else ""


def _check_open_with_token(url: str, request: Request, modern_ok: bool, handshake_ok: bool, loopback: bool, add: Callable[[Result], None]) -> None:
    """The token worked; do the tools list without one too, over any protocol the server offers?"""
    open_over = []
    if modern_ok and _lists_tools(request, url, _Era(modern=True)):
        open_over.append(MODERN)
    if handshake_ok:
        anonymous = _anonymous_handshake(request, url)
        if anonymous is not None and _lists_tools(request, url, anonymous):
            open_over.append("the handshake")
    if open_over:
        add(Result("INFO", "Token not needed", f"The tools list without a token over {' and '.join(open_over)}"))
        if loopback:
            add(Result("INFO", "No sign-in required", "Fine on this machine"))
        else:
            add(Result("WARN", "No sign-in required", "Anyone who finds this address can list and call its tools", "Add sign-in before sharing it (Sett: deploy vercel --auth supabase)"))
    else:
        add(Result("PASS", "Token accepted", "tools/list answered with it, and not without it"))


def _anonymous_handshake(request: Request, url: str) -> _Era | None:
    """A handshake session opened without the token, or None if the server won't open one."""
    status, headers, body = _post(request, url, _initialize(), None)
    info = _dict((_message(headers, body, 1) or {}).get("result"))
    if status != 200 or not info or _handshake_problems(info, headers):
        return None
    era = _Era(modern=False)
    if headers.get("mcp-session-id"):
        era.headers["mcp-session-id"] = headers["mcp-session-id"]
    era.headers["mcp-protocol-version"] = str(info["protocolVersion"])
    _post(request, url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, None, era.headers)
    return era


def _lists_tools(request: Request, url: str, era: _Era) -> bool:
    """Whether tools/list answers without a token in this era."""
    status, headers, body = _call(request, url, None, era, "tools/list", 90)
    return status == 200 and isinstance(_dict((_message(headers, body, 90) or {}).get("result")).get("tools"), list)


def _token_rejected(url: str, status: int, headers: Mapping[str, str], request: Request, add: Callable[[Result], None], *, check_sign_in: bool) -> None:
    add(Result("FAIL", "Token accepted", f"HTTP {status}", "The token may be expired, or issued for another server (its audience must be this URL)"))
    if status == 401 and check_sign_in:
        _check_sign_in(url, headers, request, add)


def _requires_sign_in(url: str, headers: Mapping[str, str], request: Request, add: Callable[[Result], None], detail: str, not_checked: str) -> None:
    add(Result("PASS", "Requires sign-in", detail))
    _check_sign_in(url, headers, request, add)
    add(Result("INFO", "Tools not checked", not_checked))


# --- Framing and replies --------------------------------------------------------------


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


def _content_type_ok(headers: Mapping[str, str]) -> bool:
    kind = headers.get("content-type", "").lower()
    return kind.startswith(("application/json", "text/event-stream"))


def _message(headers: Mapping[str, str], body: bytes, id_: int) -> dict[str, Any] | None:
    """The JSON-RPC reply to request `id_`, from JSON or an event stream, as a client reads it.

    Clients only accept application/json and text/event-stream, and match replies to
    requests by id, so anything else counts as no reply.
    """
    kind = headers.get("content-type", "").lower()
    text = body.decode(errors="replace")
    if kind.startswith("text/event-stream"):
        data: list[str] = []
        for line in [*text.splitlines(), ""]:
            if line.startswith("data:"):
                data.append(line[5:].removeprefix(" "))
            elif not line and data:
                message = _json_object("\n".join(data))
                data = []
                if _is_reply(message, id_):
                    return message
        return None
    if not kind.startswith("application/json"):
        return None
    message = _json_object(text)
    return message if _is_reply(message, id_) else None


def _is_reply(message: dict[str, Any] | None, id_: object) -> bool:
    """A JSON-RPC 2.0 reply to request `id_`: the version, the id, and exactly one of result or error."""
    if message is None or message.get("jsonrpc") != "2.0" or ("result" in message) == ("error" in message):
        return False
    reply_id = message.get("id")
    return not isinstance(reply_id, bool) and reply_id == id_  # JSON true isn't the id 1, though Python says True == 1


def _json_object(text: str | bytes) -> dict[str, Any] | None:
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _why(status: int, headers: Mapping[str, str], body: bytes) -> str:
    if status == 200 and not _content_type_ok(headers):
        return f"HTTP 200 with Content-Type {headers.get('content-type') or 'missing'}; clients only accept application/json or text/event-stream"
    return f"HTTP {status}: {_snippet(body)}" if body.strip() else f"HTTP {status}"


def _snippet(body: bytes) -> str:
    return body.decode("utf-8", errors="replace").strip().replace("\n", " ")[:160]


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _server_name(server: Mapping[str, Any]) -> str:
    return " ".join(str(v) for v in (server.get("name"), server.get("version")) if v) or "unnamed server"


def _discovered(headers: Mapping[str, str], body: bytes) -> dict[str, Any]:
    """A server/discover result that offers 2026-07-28, or {} (an error, or another reply)."""
    result = _dict((_message(headers, body, 1) or {}).get("result"))
    versions = result.get("supportedVersions")
    return result if isinstance(versions, list) and MODERN in versions else {}


def _missing_2026_fields(result: Mapping[str, Any], *, discover: bool) -> list[str]:
    """What a 2026-07-28 result lacks that the SDK's client requires."""
    problems = []
    if result.get("cacheScope") not in ("private", "public"):
        problems.append("cacheScope")
    if not isinstance(result.get("resultType"), str):
        problems.append("resultType")
    ttl = result.get("ttlMs")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0:
        problems.append("ttlMs")
    if discover:
        if not isinstance(result.get("capabilities"), dict):
            problems.append("capabilities")
        if not all(isinstance(v, str) for v in result.get("supportedVersions") or []):
            problems.append("supportedVersions")
    return problems


def _handshake_problems(info: Mapping[str, Any], headers: Mapping[str, str]) -> list[str]:
    """Why a client on the handshake would turn this initialize result down, if it would."""
    problems = []
    version = info.get("protocolVersion")
    if version not in HANDSHAKE_VERSIONS:
        problems.append(f"protocolVersion {str(version)[:40]!r} isn't one clients support ({', '.join(HANDSHAKE_VERSIONS)})")
    if not isinstance(info.get("capabilities"), dict):
        problems.append("capabilities is missing")
    server = info.get("serverInfo")
    if not isinstance(server, dict) or not isinstance(server.get("name"), str) or not isinstance(server.get("version"), str):
        problems.append("serverInfo needs a name and a version")
    session = headers.get("mcp-session-id")
    if session is not None and not HEADER_SAFE.fullmatch(session):
        problems.append("Mcp-Session-Id has characters a header can't carry")
    return problems


# --- Sign-in --------------------------------------------------------------------------


def _get(request: Request, url: str) -> tuple[int, dict[str, Any] | None]:
    """(status, JSON object or None); status 0 when there was no answer."""
    try:
        status, _, body = request("GET", url, {"Accept": "application/json"}, None)
    except TRANSPORT_ERRORS:
        return 0, None
    return status, _json_object(body) if status == 200 else None


def _usable(endpoint: object, *, issuer: bool = False) -> bool:
    """An absolute https address (plain http only on this machine), with no fragment.

    An issuer may not have a query either (RFC 8414 section 2; RFC 6749 section 3.1 for endpoints).
    """
    if not isinstance(endpoint, str):
        return False
    try:
        parts = urlsplit(endpoint)
        if parts.fragment or "#" in endpoint or (issuer and (parts.query or "?" in endpoint)):
            return False
        host = parts.hostname
        parts.port  # noqa: B018 (raises ValueError for a port that isn't a number in range)
    except ValueError:
        return False
    return bool(host) and (parts.scheme == "https" or (parts.scheme == "http" and host in LOOPBACK))


def _same_resource(resource: str, url: str) -> bool:
    """Equal as clients compare them: scheme and host ignore case, the path and query don't."""
    try:
        r, u = urlsplit(resource), urlsplit(url)
    except ValueError:
        return False
    same_site = r.scheme.lower() == u.scheme.lower() and r.netloc.lower() == u.netloc.lower()
    return same_site and r.path.rstrip("/") == u.path.rstrip("/") and r.query == u.query


def resource_covers(resource: str, url: str) -> bool:
    """The SDK client's rule: same scheme and host, and the URL's path within the resource's."""
    try:
        r, u = urlsplit(resource), urlsplit(url)
    except ValueError:
        return False
    if r.scheme.lower() != u.scheme.lower() or r.netloc.lower() != u.netloc.lower():
        return False
    return (u.path.rstrip("/") + "/").startswith(r.path.rstrip("/") + "/")


def _check_sign_in(url: str, headers: Mapping[str, str], request: Request, add: Callable[[Result], None]) -> None:
    challenge = headers.get("www-authenticate", "")
    found = re.search(r'resource_metadata=(?:"([^"]+)"|([^\s,]+))', challenge)  # quoted or not, as the SDK reads it
    linked = (found.group(1) or found.group(2)) if found else None
    parts = urlsplit(url)
    base = f"{parts.scheme}://{parts.netloc}"
    candidates = []  # the SDK client's order: the challenge's link, then path-based, then root
    if linked and not _usable(linked):
        add(Result("FAIL", "401 points to sign-in", f"resource_metadata is {linked}, not an https address", "Send the full https address of the resource metadata; clients won't use it otherwise"))
    elif linked:
        add(Result("PASS", "401 points to sign-in", "WWW-Authenticate names the resource metadata"))
        candidates.append(linked)
    else:
        add(Result("WARN", "401 points to sign-in", "No resource_metadata in WWW-Authenticate", "Clients fall back to the well-known addresses; send resource_metadata in the challenge (RFC 9728)"))
    if parts.path and parts.path != "/":
        candidates.append(f"{base}/.well-known/oauth-protected-resource{parts.path}")
    candidates.append(f"{base}/.well-known/oauth-protected-resource")

    metadata, where = None, ""
    for candidate in dict.fromkeys(candidates):
        _, data = _get(request, candidate)
        if data is not None and isinstance(data.get("resource"), str):
            metadata, where = data, candidate
            break
    if metadata is None:
        add(Result("FAIL", "Protected resource metadata", f"Nothing usable at {' or '.join(dict.fromkeys(candidates))}", "Serve RFC 9728 metadata there, naming this URL and its authorization server"))
        return
    resource = metadata["resource"]
    if _same_resource(resource, url):
        add(Result("PASS", "Protected resource metadata", f"resource = {resource}"))
    elif resource_covers(resource, url):
        add(Result("PASS", "Protected resource metadata", f"resource {resource} covers {url}"))
    else:
        add(Result("FAIL", "Protected resource metadata", f"resource is {resource}, but clients connect to {url} (from {where})", "Tokens are issued for the resource URL; it must be the address clients use, or a parent of it (Sett: <PREFIX>_PUBLIC_URL)"))
    servers = metadata.get("authorization_servers")
    if not isinstance(servers, list) or not servers or not isinstance(servers[0], str):
        add(Result("FAIL", "Authorization server named", "authorization_servers is missing, empty or not a list of addresses", "List the issuer clients sign in with"))
        return
    _check_authorization_server(servers[0], request, add)


def _issuer_form(address: str) -> str:
    """The issuer as a client compares it: a bare host gets its "/" (how the SDK parses URLs)."""
    try:
        parts = urlsplit(address)
    except ValueError:
        return address
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, parts.fragment))


def _check_authorization_server(issuer: str, request: Request, add: Callable[[Result], None]) -> None:
    if not _usable(issuer, issuer=True):
        add(Result("FAIL", "Authorization server metadata", f"The issuer {issuer} isn't an https address without a query or fragment", "List the issuer's full https address in authorization_servers (RFC 8414 forbids a query or fragment in it)"))
        return
    parts = urlsplit(issuer)
    base, path = f"{parts.scheme}://{parts.netloc}", parts.path.rstrip("/")
    if path:  # exactly the SDK client's candidates, in its order
        candidates = [f"{base}/.well-known/oauth-authorization-server{path}", f"{base}/.well-known/openid-configuration{path}", f"{base}{path}/.well-known/openid-configuration"]
    else:
        candidates = [f"{base}/.well-known/oauth-authorization-server", f"{base}/.well-known/openid-configuration"]
    metadata = None
    for candidate in candidates:
        status, data = _get(request, candidate)
        if status == 200 and data is not None:
            metadata = data
            break
        if not 200 <= status < 500:  # a server error (or no answer) stops a client's search
            add(Result("FAIL", "Authorization server metadata", f"{candidate} answered {f'HTTP {status}' if status else 'nothing'}", "Clients stop looking at a server error; fix it, or serve the metadata at an earlier address"))
            return
    if metadata is None:
        add(Result("FAIL", "Authorization server metadata", f"None found for {issuer}", "Clients read it to find where to sign in"))
        return
    problems = []
    named = metadata.get("issuer")
    if not isinstance(named, str) or _issuer_form(named) != _issuer_form(issuer):
        problems.append(f"issuer is {named or 'missing'}, but authorization_servers names {issuer}; clients compare them exactly")
    for key in ("authorization_endpoint", "token_endpoint"):
        if not _usable(metadata.get(key)):
            problems.append(f"{key} is {metadata.get(key) or 'missing'}, not an https address")
    if problems:
        add(Result("FAIL", "Authorization server metadata", "; ".join(problems), "Clients check these before signing in, and stop if they're wrong (RFC 8414)"))
    else:
        add(Result("PASS", "Authorization server metadata", issuer))
    methods = metadata.get("code_challenge_methods_supported")
    if isinstance(methods, list) and "S256" in methods:
        add(Result("PASS", "PKCE (S256)"))
    else:
        add(Result("FAIL", "PKCE (S256)", "code_challenge_methods_supported doesn't list S256", "MCP clients require PKCE and may refuse to sign in"))
    if _usable(metadata.get("registration_endpoint")):
        add(Result("PASS", "Clients can register themselves", "Dynamic client registration"))
    elif metadata.get("client_id_metadata_document_supported") is True:
        add(Result("PASS", "Clients can register themselves", "Client ID metadata documents"))
    else:
        add(Result("WARN", "Clients can register themselves", "No registration_endpoint and no client ID metadata documents", "Each client must then be registered by hand; Claude and Cursor expect to register themselves"))


# --- The endpoint and the tools -------------------------------------------------------


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
    elif status == 200 and response.get("content-type", "").lower().startswith("text/event-stream"):
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


def _check_tools(url: str, request: Request, token: str | None, era: _Era, add: Callable[[Result], None], *, strict: bool) -> tuple[int, Mapping[str, str]]:
    """Check the tools; returns tools/list's (status, headers), so a 401 or 403 can be judged.

    `strict` applies the handshake's (2025-11-25) stricter tool rules too, for servers
    that offer it.
    """
    tools: list[Any] = []
    cursor = None
    for page in range(MAX_PAGES):
        params = {"cursor": cursor} if cursor else {}
        status, headers, body = _call(request, url, token, era, "tools/list", 3 + page, params)
        if status in (401, 403) and page == 0:
            return status, headers
        result = _dict((_message(headers, body, 3 + page) or {}).get("result"))
        missing = _missing_2026_fields(result, discover=False) if era.modern and result else []
        if status != 200 or not isinstance(result.get("tools"), list) or missing:
            detail = f"tools/list is missing or has wrong {', '.join(missing)}" if missing else _why(status, headers, body)
            add(Result("FAIL", "Lists tools", detail + (f" (page {page + 1})" if page else ""), "Clients can't show any tools until tools/list answers with a valid result"))
            return status, headers
        tools += result["tools"]
        cursor = result.get("nextCursor")
        if cursor is not None and not isinstance(cursor, str):
            add(Result("FAIL", "Lists tools", f"nextCursor is {json.dumps(cursor)[:40]}, not text" + (f" (page {page + 1})" if page else ""), "Clients send nextCursor back as text to get the next page; send a string, or leave it out on the last page"))
            return status, headers
        if not cursor:
            break
    else:
        add(Result("WARN", "Lists tools", f"Stopped after {MAX_PAGES} pages; only those tools were checked", "A nextCursor that never runs out makes clients loop too"))
    add(Result("PASS", "Lists tools", f"{len(tools)} tool{'s' if len(tools) != 1 else ''}"))
    malformed = [f"{_label(t, i)} ({problem})" for i, t in enumerate(tools) if (problem := _tool_problem(t, strict=strict))]
    if malformed:
        add(Result("FAIL", "Tool definitions", f"Malformed: {'; '.join(malformed)}", "Clients validate every tool, and one malformed tool can make them reject the whole list"))
    tools = [t for t in tools if not _tool_problem(t, strict=strict)]
    bad_names = [t["name"] for t in tools if not TOOL_NAME.fullmatch(t["name"])]
    if bad_names:
        add(Result("FAIL", "Tool names", ", ".join(bad_names), "Use 1-128 letters, digits, _, - or ."))
    narrow = [t["name"] for t in tools if TOOL_NAME.fullmatch(t["name"]) and not STRICT_TOOL_NAME.fullmatch(t["name"])]
    if narrow:
        add(Result("WARN", "Tool names", f"Valid, but some clients refuse: {', '.join(narrow)}", "Claude, among others, only accepts 1-64 letters, digits, _ or -"))
    thin = [t["name"] for t in tools if len(str(t.get("description") or "").strip()) < 20]
    if thin:
        add(Result("WARN", "Tool descriptions", f"Missing or very short: {', '.join(thin)}", "The model chooses tools by their description: say what it does and when to use it"))
    else:
        add(Result("PASS", "Tool descriptions"))
    undescribed = sorted(
        f"{t['name']}.{name}"
        for t in tools
        for name, schema in (t["inputSchema"].get("properties") or {}).items()
        if isinstance(schema, dict) and not schema.get("description")
    )
    if undescribed:
        shown = ", ".join(undescribed[:8]) + (f" and {len(undescribed) - 8} more" if len(undescribed) > 8 else "")
        add(Result("WARN", "Parameter descriptions", f"Missing: {shown}", "Describe each parameter: its format, an example, its limits"))
    else:
        add(Result("PASS", "Parameter descriptions"))
    unhinted = [t["name"] for t in tools if not any(k in _dict(t.get("annotations")) for k in ("readOnlyHint", "destructiveHint"))]
    if unhinted:
        add(Result("WARN", "Read-only and destructive hints", f"None on: {', '.join(unhinted)}", "Clients use readOnlyHint and destructiveHint to decide when to ask the user first"))
    else:
        add(Result("PASS", "Read-only and destructive hints"))
    return 200, headers


def _tool_problem(tool: object, *, strict: bool) -> str:
    """Why the SDK's client would reject this tool definition, or "" if it wouldn't."""
    if not isinstance(tool, dict):
        return "not an object"
    if not isinstance(tool.get("name"), str) or not tool["name"]:
        return "no name"
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return 'inputSchema needs "type": "object"'
    annotations = tool.get("annotations")
    if annotations is not None:
        if not isinstance(annotations, dict):
            return "annotations isn't an object"
        if annotations.get("title") is not None and not isinstance(annotations["title"], str):
            return "annotations title isn't text"
        for hint in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
            if annotations.get(hint) is not None and not isinstance(annotations[hint], bool):
                return f"annotations {hint} isn't true or false"
    if "description" in tool and not isinstance(tool["description"], (str, type(None))):
        return "description isn't text"
    output = tool.get("outputSchema")
    if output is not None and not isinstance(output, dict):
        return "outputSchema isn't an object"
    if not isinstance(schema.get("properties", {}), dict):
        return "inputSchema properties must be an object"
    if strict:  # 2025-11-25 also constrains these
        for label, part in (("inputSchema", schema), ("outputSchema", output)):
            if part is None:
                continue
            if label == "outputSchema" and part.get("type") != "object":
                return 'outputSchema needs "type": "object"'
            properties = part.get("properties")
            if properties is not None and (not isinstance(properties, dict) or not all(isinstance(v, (dict, bool)) for v in properties.values())):
                return f"{label} properties must be an object of schemas"
            required = part.get("required")
            if required is not None and (not isinstance(required, list) or not all(isinstance(v, str) for v in required)):
                return f"{label} required must be a list of names"
    return ""


def _label(tool: object, index: int) -> str:
    name = tool.get("name") if isinstance(tool, dict) else None
    return str(name) if isinstance(name, str) and name else f"tool #{index + 1}"


# --- Output ---------------------------------------------------------------------------


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
