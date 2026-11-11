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
                return self.reply(405, b"", [("Allow", "POST")])
            return self.reply(404)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path != "/mcp":
                return self.reply(404)
            state["authorizations"].append(self.headers.get("Authorization"))
            if options.get("redirect_to"):
                return self.reply(307, b"", [("Location", options["redirect_to"])])
            if options.get("auth") and self.headers.get("Authorization") != "Bearer good":
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
            if method == "initialize":
                result = {"protocolVersion": "2025-11-25", "capabilities": {}, "serverInfo": {"name": "acme", "version": "1"}}
                session = "signed-in" if self.headers.get("Authorization") else "anonymous"
                return self.json({"jsonrpc": "2.0", "id": body["id"], "result": result}, headers=[("Mcp-Session-Id", session)])
            if method == "tools/list":
                state["sessions"].append(self.headers.get("Mcp-Session-Id"))
                tools = options.get("tools", TOOLS)
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
    url, state = server()
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
