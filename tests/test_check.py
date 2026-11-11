"""`sett-mcp check`, against small fake servers on localhost."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sett_mcp import check as check_module
from sett_mcp.check import check, normalize, report

TOOLS = [
    {
        "name": "acme_search_contacts",
        "description": "Search contacts by name, email or company.",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "Words to match"}}},
        "annotations": {"readOnlyHint": True},
    }
]


def serve(**options):
    """A fake MCP server; `options` switch its behaviour."""
    state = {"origins": [], "authorizations": [], "sessions": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, body=b"", headers=()):
            self.send_response(status)
            for key, value in headers:
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def json(self, data, status=200, headers=()):
            self.reply(status, json.dumps(data).encode(), [("Content-Type", "application/json"), *headers])

        def do_GET(self):
            base = f"http://127.0.0.1:{self.server.server_port}"
            state["authorizations"].append(self.headers.get("Authorization"))
            if options.get("redirect_to"):
                return self.reply(302, b"", [("Location", options["redirect_to"])])
            if self.path == "/.well-known/oauth-protected-resource/mcp":
                return self.json({"resource": options.get("resource", f"{base}/mcp"), "authorization_servers": [f"{base}/auth/v1"]})
            if self.path == "/.well-known/oauth-authorization-server/auth/v1":
                meta = {"issuer": f"{base}/auth/v1", "authorization_endpoint": f"{base}/auth/v1/oauth/authorize", "token_endpoint": f"{base}/auth/v1/oauth/token"}
                if not options.get("no_pkce"):
                    meta["code_challenge_methods_supported"] = ["S256"]
                if not options.get("no_dcr"):
                    meta["registration_endpoint"] = f"{base}/auth/v1/register"
                meta.update(options.get("metadata", {}))
                return self.json({k: v for k, v in meta.items() if v is not None})
            if self.path == "/mcp":
                if options.get("get_needs_session") and not self.headers.get("Mcp-Session-Id"):
                    return self.reply(400, b"Missing session ID")
                return self.reply(405, b"", [("Allow", "POST")])
            return self.reply(404)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path != "/mcp":
                return self.reply(404)
            state["authorizations"].append(self.headers.get("Authorization"))
            if options.get("redirect_to"):
                return self.reply(307, b"", [("Location", options["redirect_to"])])
            public = options.get("public", ()) and body.get("method") in options["public"]
            if options.get("auth") and not public and self.headers.get("Authorization") != "Bearer good":
                challenge = 'Bearer error="invalid_token"'
                if not options.get("no_challenge_link"):
                    base = f"http://127.0.0.1:{self.server.server_port}"
                    challenge += f', resource_metadata="{base}/.well-known/oauth-protected-resource/mcp"'
                return self.json({"error": "invalid_token"}, 401, [("WWW-Authenticate", challenge)])
            if self.headers.get("Origin"):
                state["origins"].append(self.headers["Origin"])
                if not options.get("any_origin"):
                    return self.reply(403)
            method = body.get("method")
            era = options.get("era", "both")
            modern = self.headers.get("Mcp-Protocol-Version") == "2026-07-28" and self.headers.get("Mcp-Method") == method
            if (modern and era == "legacy" and not options.get("discover_error_200")) or (method == "initialize" and era == "modern"):
                return self.json({"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32600, "message": "Bad Request"}}, 400)
            if method == "server/discover" and modern:
                result = {"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}, "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "acme", "version": "1"}}}
                return self.json({"jsonrpc": "2.0", "id": body["id"], "result": result})
            if method == "server/discover" and options.get("discover_error_200"):
                return self.json({"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32601, "message": "Method not found"}})
            if method == "server/discover":
                return self.json({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Missing session ID"}}, 400)
            if method == "initialize":
                result = {"protocolVersion": "2025-11-25", "capabilities": {}, "serverInfo": {"name": "acme", "version": "1"}}
                session = "signed-in" if self.headers.get("Authorization") else "anonymous"
                return self.json({"jsonrpc": "2.0", "id": body["id"], "result": result}, headers=[("Mcp-Session-Id", session)])
            if method == "tools/list":
                state["sessions"].append(self.headers.get("Mcp-Session-Id"))
                tools = options.get("tools", TOOLS)
                if options.get("pages"):
                    index = int((body.get("params") or {}).get("cursor") or 0)
                    pages = options["pages"]
                    result = {"tools": pages[index]}
                    if index + 1 < len(pages):
                        result["nextCursor"] = str(index + 1)
                    return self.json({"jsonrpc": "2.0", "id": body["id"], "result": result})
                if options.get("sse"):
                    data = f"event: message\ndata: {json.dumps({'jsonrpc': '2.0', 'id': body['id'], 'result': {'tools': tools}})}\n\n"
                    return self.reply(200, data.encode(), [("Content-Type", "text/event-stream")])
                return self.json({"jsonrpc": "2.0", "id": body["id"], "result": {"tools": tools}})
            if method == "ping":
                return self.json({"jsonrpc": "2.0", "id": body["id"], "result": {}})
            return self.reply(202)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}/mcp", state


@pytest.fixture
def server():
    servers = []

    def start(**options):
        srv, url, state = serve(**options)
        servers.append(srv)
        return url, state

    yield start
    for srv in servers:
        srv.shutdown()


def statuses(results):
    return {r.name: r.status for r in results}


def test_a_well_configured_server_with_sign_in_passes(server):
    url, _ = server(auth=True)
    results = statuses(check(url))
    for name in ("Requires sign-in", "401 points to sign-in", "Protected resource metadata", "Authorization server metadata", "PKCE (S256)", "Clients can register themselves", "GET on the endpoint"):
        assert results[name] == "PASS", name
    assert results["Tools not checked"] == "INFO"


def test_with_a_token_the_tools_are_checked_too(server):
    url, state = server(auth=True)
    results = statuses(check(url, token="good"))
    assert results["Token accepted"] == "PASS"
    assert results["Lists tools"] == "PASS" and results["Tool descriptions"] == "PASS"
    assert results["Refuses other websites"] == "PASS" and state["origins"] == ["https://example.invalid"]


def test_a_rejected_token_fails_with_a_hint(server):
    url, _ = server(auth=True)
    result = next(r for r in check(url, token="bad") if r.name == "Token accepted")
    assert result.status == "FAIL" and "audience" in result.fix


def test_a_resource_url_that_does_not_match_fails(server):
    url, _ = server(auth=True, resource="https://other.example/mcp")
    assert statuses(check(url))["Protected resource metadata"] == "FAIL"


def test_missing_pkce_fails_and_missing_registration_warns(server):
    url, _ = server(auth=True, no_pkce=True, no_dcr=True)
    results = statuses(check(url))
    assert results["PKCE (S256)"] == "FAIL" and results["Clients can register themselves"] == "WARN"


def test_a_challenge_without_the_metadata_link_warns_but_still_finds_it(server):
    url, _ = server(auth=True, no_challenge_link=True)
    results = statuses(check(url))
    assert results["401 points to sign-in"] == "WARN" and results["Protected resource metadata"] == "PASS"


def test_an_open_server_on_a_public_address_warns(server, monkeypatch):
    url, _ = server()
    monkeypatch.setattr(check_module, "LOOPBACK", set())
    results = check(url)
    assert statuses(results)["No sign-in required"] == "WARN"
    assert statuses(results)["Uses plain http"] == "FAIL"


def test_thin_tools_and_any_origin_warn(server):
    tools = [{"name": "bad name!", "description": "", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}}]
    url, _ = server(tools=tools, any_origin=True, sse=True)
    results = statuses(check(url))
    assert results["Tool names"] == "FAIL"
    assert results["Tool descriptions"] == "WARN" and results["Parameter descriptions"] == "WARN"
    assert results["Read-only and destructive hints"] == "WARN" and results["Refuses other websites"] == "WARN"


def test_a_token_gets_its_own_session_on_a_server_that_also_allows_anonymous_use(server):
    url, state = server(era="legacy")
    results = statuses(check(url, token="good"))
    assert results["Token accepted"] == "PASS" and results["Lists tools"] == "PASS"
    assert state["sessions"] == ["signed-in"]


def test_a_redirect_never_carries_the_token_to_another_origin(server):
    target, target_state = server()
    url, _ = server(redirect_to=target.replace("/mcp", "/elsewhere"))
    status, headers, _ = check_module.http_request("GET", url, {"Authorization": "Bearer good"}, None)
    assert status == 302 and headers["location"].endswith("/elsewhere")
    assert target_state["authorizations"] == []


def test_a_redirect_without_a_token_is_followed(server):
    target, target_state = server()
    url, _ = server(redirect_to=target.replace("/mcp", "/.well-known/oauth-protected-resource/mcp"))
    status, _, body = check_module.http_request("GET", url, {}, None)
    assert status == 200 and b"authorization_servers" in body and target_state["authorizations"] == [None]


def test_an_endpoint_that_redirects_posts_fails_and_the_token_stays_put(server):
    target, target_state = server()
    url, _ = server(redirect_to=target)
    results = check(url, token="good")
    result = next(r for r in results if r.name == "Answers MCP requests")
    assert result.status == "FAIL" and target in result.detail
    assert target_state["authorizations"] == []
    assert "Token accepted" not in statuses(results)


@pytest.mark.parametrize(
    "metadata",
    [
        {"issuer": "https://someone-else.example/auth/v1"},
        {"token_endpoint": None},
        {"authorization_endpoint": "/oauth/authorize"},
        {"token_endpoint": "http://plain.example/token"},
    ],
)
def test_unusable_authorization_server_metadata_fails(server, metadata):
    url, _ = server(auth=True, metadata=metadata)
    assert statuses(check(url))["Authorization server metadata"] == "FAIL"


def test_a_relative_registration_endpoint_does_not_count(server):
    url, _ = server(auth=True, metadata={"registration_endpoint": "/register"})
    assert statuses(check(url))["Clients can register themselves"] == "WARN"


def test_a_token_is_never_sent_over_plain_http_to_another_machine(server, monkeypatch):
    url, state = server(auth=True)
    monkeypatch.setattr(check_module, "LOOPBACK", set())
    results = statuses(check(url, token="good"))
    assert results["Token not sent"] == "FAIL" and results["Tools not checked"] == "INFO"
    assert "Bearer good" not in state["authorizations"]


def test_every_page_of_tools_is_checked(server):
    bad = {"name": "acme_delete_everything", "description": "", "inputSchema": {"type": "object"}}
    url, state = server(pages=[TOOLS, [bad]])
    results = check(url)
    lists = next(r for r in results if r.name == "Lists tools")
    assert lists.detail == "2 tools" and len(state["sessions"]) == 2
    assert statuses(results)["Tool descriptions"] == "WARN"


def test_a_connection_lost_after_initialize_is_reported_not_raised(server):
    url, _ = server()
    calls = []

    def flaky(method, target, headers, body):
        calls.append(method)
        if len(calls) > 4:  # after the probe, discover, initialize and initialized
            raise ConnectionResetError("connection reset by peer")
        return check_module.http_request(method, target, headers, body)

    results = check(url, request=flaky)
    assert statuses(results)["Protocol 2026-07-28"] == "PASS"
    assert statuses(results)["Connection"] == "FAIL"


def test_malformed_tools_are_reported_and_the_rest_still_checked(server):
    tools = [
        TOOLS[0],
        {"name": "acme_string_schema", "description": "A tool whose schema is a string.", "inputSchema": "nope"},
        {"name": "acme_list_properties", "description": "A tool whose properties is a list.", "inputSchema": {"type": "object", "properties": ["q"]}},
        {"name": "acme_odd_annotations", "description": "A tool whose annotations is a string.", "inputSchema": {"type": "object"}, "annotations": "x"},
        "not a tool",
    ]
    url, _ = server(tools=tools)
    results = check(url)
    malformed = next(r for r in results if r.name == "Tool definitions")
    assert malformed.status == "FAIL"
    for name in ("acme_string_schema", "acme_list_properties", "acme_odd_annotations", "tool #5"):
        assert name in malformed.detail
    assert statuses(results)["Parameter descriptions"] == "PASS"


def test_a_non_object_result_fails_cleanly(server):
    url, _ = server()

    def odd(method, target, headers, body):
        return 200, {"content-type": "application/json"}, b'{"jsonrpc": "2.0", "id": 1, "result": ["x"]}'

    assert statuses(check(url, request=odd))["Answers MCP requests"] == "FAIL"


def test_a_server_offering_both_protocols_passes_both(server):
    url, _ = server()
    results = statuses(check(url))
    assert results["Protocol 2026-07-28"] == "PASS" and results["Handshake protocol"] == "PASS"
    assert results["Lists tools"] == "PASS" and results["Refuses other websites"] == "PASS"


def test_a_2026_only_server_passes_and_warns_about_older_clients(server):
    url, _ = server(era="modern")
    results = check(url)
    assert statuses(results)["Protocol 2026-07-28"] == "PASS" and statuses(results)["Handshake protocol"] == "WARN"
    assert statuses(results)["Lists tools"] == "PASS"
    assert not [r for r in results if r.status == "FAIL"]


def test_a_handshake_only_server_still_passes(server):
    url, _ = server(era="legacy")
    results = check(url)
    assert statuses(results)["Protocol 2026-07-28"] == "INFO" and statuses(results)["Handshake protocol"] == "PASS"
    assert statuses(results)["Lists tools"] == "PASS"
    assert not [r for r in results if r.status == "FAIL"]


def test_the_get_probe_carries_the_session(server):
    url, _ = server(era="legacy", get_needs_session=True)
    assert statuses(check(url))["GET on the endpoint"] == "PASS"


def test_a_relative_resource_metadata_link_fails_without_a_traceback():
    def odd(method, target, headers, body):
        if method == "POST":
            return 401, {"www-authenticate": 'Bearer resource_metadata="relative/path"'}, b""
        return 404, {}, b""

    results = statuses(check("https://srv.example/mcp", request=odd))
    assert results["401 points to sign-in"] == "FAIL" and results["Protected resource metadata"] == "FAIL"


def test_an_issuer_that_is_not_an_https_address_fails(server):
    def odd(method, target, headers, body):
        if method == "POST":
            return 401, {"www-authenticate": 'Bearer resource_metadata="https://srv.example/.well-known/oauth-protected-resource/mcp"'}, b""
        if "oauth-protected-resource" in target:
            return 200, {}, json.dumps({"resource": "https://srv.example/mcp", "authorization_servers": ["auth/v1"]}).encode()
        return 404, {}, b""

    assert statuses(check("https://srv.example/mcp", request=odd))["Authorization server metadata"] == "FAIL"


@pytest.mark.parametrize("servers", [True, "https://x.example", [], [1]])
def test_odd_authorization_servers_fail_cleanly(servers):
    def odd(method, target, headers, body):
        if method == "POST":
            return 401, {"www-authenticate": f'Bearer resource_metadata="{target.replace("/mcp", "/.well-known/oauth-protected-resource/mcp")}"'}, b""
        if "oauth-protected-resource" in target:
            return 200, {}, json.dumps({"resource": "https://srv.example/mcp", "authorization_servers": servers}).encode()
        return 405, {}, b""

    assert statuses(check("https://srv.example/mcp", request=odd))["Authorization server named"] == "FAIL"


def test_a_discover_error_with_http_200_falls_back_to_the_handshake(server):
    url, _ = server(era="legacy", discover_error_200=True, auth=True, public={"server/discover"})
    results = statuses(check(url))
    assert results["Requires sign-in"] == "PASS" and results["Protected resource metadata"] == "PASS"
    assert "Answers MCP requests" not in results


def test_public_discovery_with_protected_tools_is_sign_in_working(server):
    url, _ = server(auth=True, public={"server/discover", "initialize", "notifications/initialized"})
    results = check(url)
    named = statuses(results)
    assert named["Requires sign-in"] == "PASS" and named["Authorization server metadata"] == "PASS"
    assert "No sign-in required" not in named and "Lists tools" not in named


def test_an_open_server_is_only_called_open_once_its_tools_list_without_a_token(server, monkeypatch):
    url, _ = server()
    monkeypatch.setattr(check_module, "LOOPBACK", set())
    names = [r.name for r in check(url)]
    assert names.index("Lists tools") < names.index("No sign-in required")


def test_plain_http_resource_metadata_fails_on_a_public_server():
    def odd(method, target, headers, body):
        if method == "POST":
            return 401, {"www-authenticate": 'Bearer resource_metadata="http://metadata.example/.well-known/oauth-protected-resource/mcp"'}, b""
        return 404, {}, b""

    assert statuses(check("https://srv.example/mcp", request=odd))["401 points to sign-in"] == "FAIL"


@pytest.mark.parametrize("schema", [{"type": "array", "properties": {}}, {"properties": {}}])
def test_an_input_schema_that_is_not_an_object_is_malformed(server, schema):
    tools = [TOOLS[0], {"name": "acme_odd", "description": "A tool whose schema isn't an object.", "inputSchema": schema}]
    url, _ = server(tools=tools)
    result = next(r for r in check(url) if r.name == "Tool definitions")
    assert result.status == "FAIL" and "acme_odd" in result.detail


def test_a_reply_with_the_wrong_id_is_ignored(server):
    url, _ = server()

    def wrong_ids(method, target, headers, body):
        status, response_headers, raw = check_module.http_request(method, target, headers, body)
        if body and json.loads(body).get("method") == "tools/list":
            data = json.loads(raw)
            data["id"] = 999
            raw = json.dumps(data).encode()
        return status, response_headers, raw

    assert statuses(check(url, request=wrong_ids))["Lists tools"] == "FAIL"


def test_an_unreachable_server_fails_cleanly():
    results = check("http://127.0.0.1:9/mcp")
    assert statuses(results)["Server reachable"] == "FAIL"


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("my-server.vercel.app", "https://my-server.vercel.app/mcp"),
        ("https://My-Server.vercel.app/", "https://my-server.vercel.app/mcp"),
        ("https://x.example/custom/path/", "https://x.example/custom/path"),
    ],
)
def test_normalize(given, expected):
    assert normalize(given) == expected


def test_report_exit_code():
    from sett_mcp.check import Result

    lines = []
    assert report([Result("PASS", "a"), Result("WARN", "b", "x", "fix it")], lines.append) == 0
    assert report([Result("FAIL", "c", "y", "fix")], lines.append) == 1
    assert any("-> fix it" in line for line in lines)
