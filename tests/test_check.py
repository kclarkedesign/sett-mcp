"""`sett-mcp check`, against small fake servers on localhost."""

from __future__ import annotations

import http.client
import json
import os
import random
import threading
import time
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
    state = {"origins": [], "authorizations": [], "sessions": [], "initialized": set()}

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
            self.reply(status, json.dumps(data).encode(), [("Content-Type", options.get("content_type", "application/json")), *headers])

        def stream_open(self, data):
            """An event stream that stays open: the reply (unless pings_only), then pings forever."""
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            try:
                if not options.get("pings_only"):
                    self.wfile.write(f"data: {json.dumps(data)}\n\n".encode())
                    self.wfile.flush()
                for _ in range(600):
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                pass

        def finish_result(self, result, modern):
            """2026-07-28 results carry cacheScope, resultType and ttlMs; the handshake's don't."""
            if modern and not options.get("incomplete_2026"):
                result = {"cacheScope": "private", "resultType": "complete", "ttlMs": 0, **result}
            return result

        def do_GET(self):
            base = f"http://127.0.0.1:{self.server.server_port}"
            state["authorizations"].append(self.headers.get("Authorization"))
            if options.get("redirect_to"):
                return self.reply(302, b"", [("Location", options["redirect_to"])])
            prm_path = "/.well-known/oauth-protected-resource" + ("" if options.get("prm_root_only") else "/mcp")
            if self.path == prm_path:
                resource = base if options.get("resource_parent") else options.get("resource", f"{base}/mcp")
                if options.get("resource_upper"):
                    resource = f"{base}/MCP"
                if options.get("resource_host_upper"):
                    resource = f"HTTP://127.0.0.1:{self.server.server_port}/mcp"  # the scheme ignores case, like the host
                return self.json({"resource": resource, "authorization_servers": [options.get("issuer", f"{base}/auth/v1")]})
            as_path = "/auth/v1/.well-known/oauth-authorization-server" if options.get("as_appended_only") else "/.well-known/oauth-authorization-server/auth/v1"
            if options.get("as_5xx") and self.path == "/.well-known/oauth-authorization-server/auth/v1":
                return self.reply(500, b"oops")
            if options.get("as_5xx"):
                as_path = "/.well-known/openid-configuration/auth/v1"
            if self.path == as_path:
                meta = {"issuer": f"{base}/auth/v1", "authorization_endpoint": f"{base}/auth/v1/oauth/authorize", "token_endpoint": f"{base}/auth/v1/oauth/token"}
                if not options.get("no_pkce"):
                    meta["code_challenge_methods_supported"] = ["S256"]
                if not options.get("no_dcr"):
                    meta["registration_endpoint"] = f"{base}/auth/v1/register"
                meta.update(options.get("metadata", {}))
                return self.json({k: v for k, v in meta.items() if v is not None})
            if self.path == "/mcp" or (options.get("slash") and self.path == "/mcp/"):
                if options.get("get_needs_session") and not self.headers.get("Mcp-Session-Id"):
                    return self.reply(400, b"Missing session ID")
                return self.reply(405, b"", [("Allow", "POST")])
            return self.reply(404)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if options.get("slash") and self.path == "/mcp":  # mounted at /mcp/, as Starlette does
                return self.reply(307, b"", [("Location", f"http://127.0.0.1:{self.server.server_port}/mcp/")])
            if self.path != ("/mcp/" if options.get("slash") else "/mcp"):
                return self.reply(404)
            state["authorizations"].append(self.headers.get("Authorization"))
            if options.get("redirect_to"):
                return self.reply(307, b"", [("Location", options["redirect_to"])])
            public = options.get("public", ()) and body.get("method") in options["public"]
            if "open_pairs" in options:  # which protocol's which method works without a token
                kind = "modern" if self.headers.get("Mcp-Protocol-Version") == "2026-07-28" else "handshake"
                method_ = body.get("method")
                if method_ in ("notifications/initialized", "ping"):
                    method_ = "initialize"
                public = (kind, method_) in options["open_pairs"]
            if options.get("public_handshake_only") and self.headers.get("Mcp-Protocol-Version") != "2026-07-28":
                public = True
            if options.get("handshake_rejects_token") and self.headers.get("Authorization") and self.headers.get("Mcp-Protocol-Version") != "2026-07-28":
                return self.json({"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32600, "message": "No tokens here"}}, 400)
            if options.get("auth") and not public and self.headers.get("Authorization") != "Bearer good":
                if options.get("deny_status") == 403:  # wrong: 403 is for a valid token without enough permission
                    return self.reply(403, b'{"error": "forbidden"}', [("Content-Type", "application/json")])
                link = f"http://127.0.0.1:{self.server.server_port}/.well-known/oauth-protected-resource/mcp"
                challenge = 'Bearer error="invalid_token"'
                if not options.get("no_challenge_link"):
                    challenge += f", resource_metadata={link}" if options.get("unquoted") else f', resource_metadata="{link}"'
                if options.get("challenge"):  # a challenge written out in full; {link} is the metadata address
                    challenge = options["challenge"].format(link=link)
                return self.reply(401, b'{"error": "invalid_token"}', [("Content-Type", "application/json"), ("WWW-Authenticate", challenge)])
            if self.headers.get("Origin"):
                state["origins"].append(self.headers["Origin"])
                if not options.get("any_origin"):
                    return self.reply(403)
            method = body.get("method")
            era = options.get("era", "both")
            modern = self.headers.get("Mcp-Protocol-Version") == "2026-07-28" and self.headers.get("Mcp-Method") == method
            if modern and method == "server/discover" and options.get("discover_error"):  # e.g. HeaderMismatch
                return self.json({"jsonrpc": "2.0", "id": body.get("id"), "error": options["discover_error"]}, 400)
            if (modern and era == "legacy" and not options.get("discover_error_200")) or (method == "initialize" and era == "modern"):
                return self.json({"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32600, "message": "Bad Request"}}, 400)
            if method == "server/discover" and modern:
                result = {"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}, "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "acme", "version": "1"}}}
                return self.json({"jsonrpc": "2.0", "id": body["id"], "result": self.finish_result(result, modern)})
            if method == "server/discover" and options.get("discover_error_200"):
                return self.json({"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32601, "message": "Method not found"}})
            if method == "server/discover":
                return self.json({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Missing session ID"}}, 400)
            if method == "initialize":
                result = {"protocolVersion": options.get("handshake_version", "2025-11-25"), "capabilities": {}, "serverInfo": {"name": "acme", "version": "1"}}
                session = "signed-in" if self.headers.get("Authorization") else "anonymous"
                return self.json({"jsonrpc": "2.0", "id": body["id"], "result": result}, headers=[("Mcp-Session-Id", session)])
            if method == "notifications/initialized":
                state["initialized"].add(self.headers.get("Mcp-Session-Id"))
                if "initialized_status" in options:
                    return self.reply(options["initialized_status"])
            if method == "tools/list" and not modern:
                if options.get("handshake_tools_malformed"):
                    bad = [*TOOLS, {"name": "acme_odd", "description": "Malformed only over the handshake.", "inputSchema": {"type": "object", "required": "q"}}]
                    return self.json({"jsonrpc": "2.0", "id": body["id"], "result": {"tools": bad}})
                if options.get("handshake_endless"):
                    return self.json({"jsonrpc": "2.0", "id": body["id"], "result": {"tools": TOOLS, "nextCursor": "again"}})
                if options.get("handshake_tools_broken"):
                    return self.json({"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32600, "message": "Bad session"}}, 400)
                if options.get("strict_lifecycle") and self.headers.get("Mcp-Session-Id") not in state["initialized"]:
                    return self.json({"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32600, "message": "Not initialized"}}, 400)
            if method == "tools/list":
                state["sessions"].append(self.headers.get("Mcp-Session-Id"))
                tools = options.get("tools", TOOLS)
                if options.get("pages"):
                    index = int((body.get("params") or {}).get("cursor") or 0)
                    pages = options["pages"]
                    result = {"tools": pages[index]}
                    if index + 1 < len(pages):
                        result["nextCursor"] = options.get("cursor", str(index + 1))
                    return self.json({"jsonrpc": "2.0", "id": body["id"], "result": self.finish_result(result, modern)})
                reply = {"jsonrpc": "2.0", "id": body["id"], "result": self.finish_result({"tools": tools}, modern)}
                if options.get("no_jsonrpc"):
                    reply.pop("jsonrpc")
                if options.get("sse_open"):
                    return self.stream_open(reply)
                if options.get("sse"):  # pretty-printed across several data: lines, which SSE joins
                    lines = "".join(f"data: {line}\n" for line in json.dumps(reply, indent=1).splitlines())
                    data = f"event: message\n: a comment\n{lines}\n"
                    return self.reply(200, data.encode(), [("Content-Type", "text/event-stream")])
                return self.json(reply)
            if method == "ping":
                return self.json({"jsonrpc": "2.0", "id": body["id"], "result": {}})
            return self.reply(202)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    # A short poll interval: shutdown() waits for one, which made every test's teardown take half a second.
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
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
    assert results["Lists tools"] == "PASS"
    assert state["sessions"][0] == "signed-in"


def test_a_redirect_never_carries_the_token_to_another_origin(server):
    target, target_state = server()
    url, _ = server(redirect_to=target.replace("/mcp", "/elsewhere"))
    status, headers, _ = check_module.http_request("GET", url, {"Authorization": "Bearer good"}, None)
    assert status == 302 and headers["location"].endswith("/elsewhere")
    assert target_state["authorizations"] == []


def test_a_redirect_to_another_origin_is_not_followed_even_without_a_token(server):
    target, target_state = server()
    url, _ = server(redirect_to=target.replace("/mcp", "/.well-known/oauth-protected-resource/mcp"))
    status, _, _ = check_module.http_request("GET", url, {}, None)
    assert status == 302 and target_state["authorizations"] == []


def test_a_same_origin_post_redirect_is_followed_as_clients_do(server):
    url, _ = server(slash=True)
    results = check(url)
    named = statuses(results)
    assert named["Redirect"] == "INFO" and named["Lists tools"] == "PASS"
    assert not [r for r in results if r.status == "FAIL"]


def test_the_address_given_is_kept_including_a_trailing_slash(server):
    url, _ = server(slash=True)
    results = check(url + "/")
    assert results[0].detail == url + "/" and "Redirect" not in statuses(results)
    assert not [r for r in results if r.status == "FAIL"]


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
    assert lists.detail == "2 tools" and len(state["sessions"]) == 4  # both pages, over both protocols
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
        ("https://My-Server.vercel.app", "https://my-server.vercel.app/mcp"),
        ("https://My-Server.vercel.app/", "https://my-server.vercel.app/"),
        ("https://x.example/custom/path/", "https://x.example/custom/path/"),
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


# --- From the adversarial review ------------------------------------------------------


@pytest.fixture
def short_deadline(monkeypatch):
    monkeypatch.setattr(check_module, "DEADLINE", 2.0)


@pytest.mark.parametrize("pings_only", [False, True])
def test_an_event_stream_left_open_never_hangs_the_check(server, short_deadline, pings_only):
    url, _ = server(sse_open=True, pings_only=pings_only)
    started = time.monotonic()
    results = statuses(check(url))
    assert time.monotonic() - started < 15
    if pings_only:  # no reply ever came
        assert results["Connection"] == "FAIL"
    else:  # the reply came, then the stream stayed open: read up to the reply, as clients do
        assert results["Lists tools"] == "PASS"


def test_a_token_with_a_trailing_line_break_is_cleaned_up(server):
    url, state = server(auth=True)
    assert statuses(check(url, token="good\r\n"))["Token accepted"] == "PASS"
    assert "Bearer good" in state["authorizations"]


@pytest.mark.parametrize("token", ["“sk-secret-123”", "sk secret", "sk-secret\n123"])
def test_a_token_a_header_cannot_carry_is_refused_and_never_printed(server, token):
    url, state = server(auth=True)
    lines = []
    report(check(url, token=token), lines.append)
    assert any("Token not sent" in line for line in lines)
    assert not any("sk-secret" in line or "sk secret" in line for line in lines)
    assert all(a is None for a in state["authorizations"])


def test_a_pasted_bearer_prefix_is_dropped(server):
    url, state = server(auth=True)
    assert statuses(check(url, token="Bearer good"))["Token accepted"] == "PASS"
    assert "Bearer good" in state["authorizations"] and "Bearer Bearer good" not in state["authorizations"]


def test_the_token_is_never_printed_even_if_the_server_echoes_it(server):
    def echo(method, target, headers, body):
        return 500, {"content-type": "text/plain"}, f"bad token {headers.get('Authorization', '')}".encode()

    lines = []
    report(check("https://srv.example/mcp", token="sk-live-abc", request=echo), lines.append)
    assert not any("sk-live-abc" in line for line in lines)


@pytest.mark.parametrize(
    "reply",
    [
        {"protocolVersion": "2025-11-25\n", "capabilities": {}, "serverInfo": {"name": "a", "version": "1"}},
        {"protocolVersion": "2025-11-25", "capabilities": {}, "serverInfo": {"name": "a", "version": "1"}, "_session": "sé"},
    ],
)
def test_server_values_a_header_cannot_carry_are_reported_not_raised(reply):
    session = reply.pop("_session", "s1")

    def odd(method, target, headers, body):
        message = json.loads(body or b"{}")
        if message.get("method") == "initialize":
            data = {"jsonrpc": "2.0", "id": 1, "result": reply}
            return 200, {"content-type": "application/json", "mcp-session-id": session}, json.dumps(data).encode()
        return 400, {"content-type": "application/json"}, b"{}"

    results = check("https://srv.example/mcp", request=odd)
    assert statuses(results)["Handshake protocol"] == "FAIL"


@pytest.mark.parametrize("address", ["https://[oops/x", "http://[oops/x", "https://auth..example/"])
def test_unusable_addresses_from_a_server_are_reported_not_raised(address):
    def odd(method, target, headers, body):
        if method == "POST":
            return 401, {"www-authenticate": f'Bearer resource_metadata="{address}"'}, b""
        return 404, {}, b""

    results = statuses(check("https://srv.example/mcp", request=odd))  # no traceback
    assert results["Protected resource metadata"] == "FAIL"


@pytest.mark.parametrize("address", ["https://[oops/x", "https://auth..example/"])
def test_unusable_addresses_are_unusable_through_the_real_transport(address):
    assert check_module.within_origin("https://srv.example/mcp", address) is False
    with pytest.raises(check_module.TRANSPORT_ERRORS):
        check_module.http_request("GET", address, {}, None)


def test_a_redirect_to_an_unusable_address_is_reported_not_raised(server):
    url, _ = server(redirect_to="http://[oops/x")
    status, _, _ = check_module.http_request("GET", url, {}, None)
    assert status == 302


def test_an_unparseable_address_given_by_the_user_fails_cleanly():
    assert statuses(check("https://[::1/mcp"))["Address"] == "FAIL"


def test_an_open_server_checked_with_a_token_is_still_called_open(server):
    url, _ = server()
    results = statuses(check(url, token="anything-at-all"))
    assert results["No sign-in required"] == "INFO" and results["Token not needed"] == "INFO"  # INFO: on this machine
    assert "Token accepted" not in results


@pytest.mark.parametrize("era", ["both", "modern"])
def test_2026_replies_missing_required_fields_fail(server, era):
    url, _ = server(era=era, incomplete_2026=True)
    results = statuses(check(url))
    assert results["Protocol 2026-07-28"] == "FAIL"


def test_a_2026_tools_list_missing_required_fields_fails(server):
    url, _ = server(era="modern")

    def strip(method, target, headers, body):
        status, found, raw = check_module.http_request(method, target, headers, body)
        if body and json.loads(body).get("method") == "tools/list":
            data = json.loads(raw)
            for key in ("cacheScope", "resultType", "ttlMs"):
                data["result"].pop(key, None)
            raw = json.dumps(data).encode()
        return status, found, raw

    result = next(r for r in check(url, request=strip) if r.name == "Lists tools")
    assert result.status == "FAIL" and "cacheScope" in result.detail


def test_a_reply_with_the_wrong_content_type_fails(server):
    url, _ = server(content_type="text/html")
    result = next(r for r in check(url) if r.name == "Answers MCP requests")
    assert result.status == "FAIL" and "text/html" in result.detail


def test_a_rejected_token_on_protected_tools_is_reported_with_the_sign_in_checks(server):
    url, _ = server(auth=True, public={"server/discover", "initialize", "notifications/initialized"})
    results = statuses(check(url, token="expired"))
    assert results["Token accepted"] == "FAIL" and results["Protected resource metadata"] == "PASS"
    assert "Lists tools" not in results


@pytest.mark.parametrize("version", ["2024-10-07", "garbage"])
def test_an_unsupported_handshake_version_fails(server, version):
    url, _ = server(era="legacy", handshake_version=version)
    assert statuses(check(url))["Handshake protocol"] == "FAIL"


@pytest.mark.parametrize(
    "tool",
    [
        {"inputSchema": {"type": "object", "required": "q"}},
        {"inputSchema": {"type": "object"}, "outputSchema": {"type": "array"}},
        {"inputSchema": {"type": "object", "properties": {"q": "string"}}},
    ],
)
def test_tool_definitions_the_handshake_rejects_fail(server, tool):
    tools = [TOOLS[0], {"name": "acme_odd", "description": "A tool with an odd schema somewhere.", **tool}]
    url, _ = server(era="legacy", tools=tools)  # handshake only: its stricter rules apply to the tool list
    result = next(r for r in check(url) if r.name == "Tool definitions")
    assert result.status == "FAIL" and "acme_odd" in result.detail and "whole list" in result.fix

    url, _ = server(tools=tools)  # both protocols: the handshake's own reply is checked with its rules
    result = next(r for r in check(url) if r.name == "Tools over the handshake")
    assert result.status == "FAIL" and "acme_odd" in result.detail


def test_protected_resource_metadata_only_at_the_root_is_found(server):
    url, _ = server(auth=True, prm_root_only=True, no_challenge_link=True)
    results = statuses(check(url))
    assert results["Protected resource metadata"] == "PASS"


def test_an_unquoted_resource_metadata_link_is_read(server):
    url, _ = server(auth=True, unquoted=True)
    assert statuses(check(url))["401 points to sign-in"] == "PASS"


def test_a_parent_resource_passes_as_the_sdk_client_accepts_it(server):
    url, _ = server(auth=True, resource_parent=True)
    result = next(r for r in check(url) if r.name == "Protected resource metadata")
    assert result.status == "PASS" and "covers" in result.detail


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({"as_appended_only": True}, "FAIL"),  # a location the SDK's client never tries
        ({"as_5xx": True}, "FAIL"),  # a server error stops a client's search
    ],
)
def test_authorization_server_discovery_matches_the_sdk(server, options, expected):
    url, _ = server(auth=True, **options)
    assert statuses(check(url))["Authorization server metadata"] == expected


def test_an_issuer_differing_by_a_trailing_slash_fails(server):
    url, _ = server(auth=True)
    base = url.removesuffix("/mcp")
    url2, _ = server(auth=True, metadata={"issuer": f"{base}/auth/v1/"})
    assert statuses(check(url2))["Authorization server metadata"] == "FAIL"


def test_tool_names_with_dots_warn_and_invalid_ones_fail(server):
    tools = [
        {**TOOLS[0], "name": "acme.search"},
        {**TOOLS[0], "name": "bad name"},
        {**TOOLS[0], "name": "acme_ok\n"},
    ]
    url, _ = server(tools=tools)
    lines = [r for r in check(url) if r.name == "Tool names"]
    assert {r.status for r in lines} == {"FAIL", "WARN"}
    assert "acme.search" in next(r.detail for r in lines if r.status == "WARN")


def test_repeated_www_authenticate_headers_keep_the_metadata_link(server):
    url, _ = server(auth=True)

    def doubled(method, target, headers, body):
        status, found, raw = check_module.http_request(method, target, headers, body)
        if status == 401:
            found = {**found, "www-authenticate": found["www-authenticate"] + ', Basic realm="gw"'}
        return status, found, raw

    assert statuses(check(url, request=doubled))["401 points to sign-in"] == "PASS"


def test_multi_line_sse_data_is_joined(server):
    url, _ = server(sse=True)
    assert statuses(check(url))["Lists tools"] == "PASS"


def test_after_token_not_sent_the_hint_does_not_repeat_add_token(server, monkeypatch):
    url, _ = server(auth=True)
    monkeypatch.setattr(check_module, "LOOPBACK", set())
    hint = next(r for r in check(url, token="good") if r.name == "Tools not checked")
    assert "https" in hint.detail


def test_a_localhost_check_never_goes_through_a_proxy(server, monkeypatch):
    url, _ = server(auth=True)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")  # nothing listens there
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    assert statuses(check(url, token="good"))["Token accepted"] == "PASS"


def test_ctrl_c_exits_quietly(monkeypatch, capsys):
    from sett_mcp import cli

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("getpass.getpass", interrupted)
    with pytest.raises(SystemExit) as exit_:
        cli.main(["check", "https://srv.example/mcp", "--token", "-"])
    assert exit_.value.code == 130


# --- Against the real MCP Python SDK --------------------------------------------------


def _sdk_server(auth_issuer=None, header_tool=False):
    """A real MCPServer on a free port, optionally behind the SDK's own bearer-token check."""
    mcp_server = pytest.importorskip("mcp.server.mcpserver")
    uvicorn = pytest.importorskip("uvicorn")
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    options = {}
    if auth_issuer:
        from mcp.server.auth.provider import AccessToken
        from mcp.server.auth.settings import AuthSettings

        class Verifier:
            async def verify_token(self, token):
                return AccessToken(token=token, client_id="test", scopes=[]) if token == "good" else None

        options = {"token_verifier": Verifier(), "auth": AuthSettings(issuer_url=auth_issuer, resource_server_url=f"http://127.0.0.1:{port}/mcp")}
    app = mcp_server.MCPServer("sdk-demo", **options)

    @app.tool()
    def echo(text: str) -> str:
        """Echo the text back to the caller, for testing."""
        return text

    if header_tool:  # a parameter the 2026-07-28 transport copies into an Mcp-Param-Region header
        from pydantic import Field

        @app.tool()
        def regional(region: str = Field(..., json_schema_extra={"x-mcp-header": "Region"})) -> str:
            """Return the region it was given, which clients also send as a header."""
            return region

    config = uvicorn.Config(app.streamable_http_app(), host="127.0.0.1", port=port, log_level="error")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    return srv, f"http://127.0.0.1:{port}/mcp"


def test_a_real_sdk_server_passes_both_protocols():
    srv, url = _sdk_server()
    try:
        results = check(url)
    finally:
        srv.should_exit = True
    named = statuses(results)
    assert named["Protocol 2026-07-28"] == "PASS" and named["Handshake protocol"] == "PASS"
    assert named["Lists tools"] == "PASS"
    assert not [r for r in results if r.status == "FAIL"], [r for r in results if r.status == "FAIL"]


def test_a_real_sdk_server_with_sign_in(server):
    fake, _ = server()  # serves the authorization server's metadata at /auth/v1
    issuer = fake.removesuffix("/mcp") + "/auth/v1"
    srv, url = _sdk_server(auth_issuer=issuer)
    try:
        anonymous = statuses(check(url))
        signed_in = check(url, token="good")
        rejected = statuses(check(url, token="bad"))
    finally:
        srv.should_exit = True
    assert anonymous["Requires sign-in"] == "PASS" and anonymous["Protected resource metadata"] == "PASS"
    assert anonymous["Authorization server metadata"] == "PASS"
    named = statuses(signed_in)
    assert named["Token accepted"] == "PASS" and named["Lists tools"] == "PASS"
    assert not [r for r in signed_in if r.status == "FAIL"], [r for r in signed_in if r.status == "FAIL"]
    assert rejected["Token accepted"] == "FAIL"


# --- Codex, after the review fixes ----------------------------------------------------


def test_public_tools_over_2026_are_found_when_only_the_handshake_needs_a_token(server, monkeypatch):
    url, _ = server(auth=True, public={"server/discover", "tools/list", "ping"})
    monkeypatch.setattr(check_module, "LOOPBACK", set())
    results = statuses(check(url))
    assert results["No sign-in required"] == "WARN" and "Requires sign-in" not in results
    assert results["Handshake protocol"] == "INFO"


def test_a_short_token_is_redacted_too():
    def echo(method, target, headers, body):
        return 500, {"content-type": "text/plain"}, f"bad token {headers.get('Authorization', '')}".encode()

    lines = []
    report(check("https://srv.example/mcp", token="k9Zq", request=echo), lines.append)
    assert not any("k9Zq" in line for line in lines)


def test_tools_over_the_handshake_are_checked_when_both_protocols_are_offered(server):
    url, _ = server(handshake_tools_broken=True)
    results = statuses(check(url))
    assert results["Lists tools"] == "PASS" and results["Tools over the handshake"] == "FAIL"


def test_the_anonymous_handshake_session_is_completed_before_listing_tools(server):
    url, _ = server(era="legacy", strict_lifecycle=True)
    results = statuses(check(url, token="anything-at-all"))
    assert results["Token not needed"] == "INFO" and "Token accepted" not in results


def test_a_reply_without_jsonrpc_2_0_is_not_accepted(server):
    url, _ = server(no_jsonrpc=True)
    assert statuses(check(url))["Lists tools"] == "FAIL"


@pytest.mark.parametrize("cursor", [[], 2, {"page": 2}])
def test_a_cursor_that_is_not_text_fails(server, cursor):
    url, _ = server(pages=[TOOLS, TOOLS], cursor=cursor)
    result = next(r for r in check(url) if r.name == "Lists tools")
    assert result.status == "FAIL" and "nextCursor" in result.detail


def test_a_public_handshake_is_found_when_2026_asks_for_a_token(server, monkeypatch):
    url, _ = server(auth=True, public={"initialize", "notifications/initialized", "tools/list", "ping"}, era="legacy")
    monkeypatch.setattr(check_module, "LOOPBACK", set())
    results = statuses(check(url))
    assert results["No sign-in required"] == "WARN" and "Requires sign-in" not in results


def test_a_resource_differing_only_in_path_case_fails(server):
    url, _ = server(auth=True, resource_upper=True)
    assert statuses(check(url))["Protected resource metadata"] == "FAIL"


def test_a_resource_differing_only_in_scheme_case_passes(server):
    url, _ = server(auth=True, resource_host_upper=True)
    assert statuses(check(url))["Protected resource metadata"] == "PASS"


def test_malformed_tools_over_the_handshake_fail(server):
    url, _ = server(handshake_tools_malformed=True)
    result = next(r for r in check(url) if r.name == "Tools over the handshake")
    assert result.status == "FAIL" and "acme_odd" in result.detail


def test_endless_pagination_over_the_handshake_fails(server):
    url, _ = server(handshake_endless=True)
    result = next(r for r in check(url) if r.name == "Tools over the handshake")
    assert result.status == "FAIL" and "50 pages" in result.detail


def test_a_public_handshake_is_found_even_when_the_token_unlocks_2026(server):
    url, _ = server(auth=True, public_handshake_only=True)
    results = statuses(check(url, token="good"))
    assert results["Token not needed"] == "INFO" and "Token accepted" not in results


@pytest.mark.parametrize("era", ["modern", "both"])
def test_list_properties_never_crash_on_any_protocol(server, era):
    tools = [TOOLS[0], {"name": "acme_odd", "description": "Properties sent as a list, not an object.", "inputSchema": {"type": "object", "properties": []}}]
    url, _ = server(era=era, tools=tools)
    result = next(r for r in check(url) if r.name == "Tool definitions")
    assert result.status == "FAIL" and "acme_odd" in result.detail


@pytest.mark.parametrize("endpoint", ["https://:443/token", "https://auth.example:bad/token", "https://auth.example:99999/token"])
def test_oauth_urls_need_a_host_and_a_valid_port(server, endpoint):
    url, _ = server(auth=True, metadata={"token_endpoint": endpoint})
    assert statuses(check(url))["Authorization server metadata"] == "FAIL"


def test_a_boolean_reply_id_is_not_the_number_one(server):
    url, _ = server()

    def bool_ids(method, target, headers, body):
        status, found, raw = check_module.http_request(method, target, headers, body)
        if body and json.loads(body).get("id") == 1 and raw:
            data = json.loads(raw)
            data["id"] = True
            raw = json.dumps(data).encode()
        return status, found, raw

    assert statuses(check(url, request=bool_ids))["Answers MCP requests"] == "FAIL"


@pytest.mark.parametrize("annotations", [{"readOnlyHint": "false"}, {"destructiveHint": 1}, {"title": 5}])
def test_annotation_values_of_the_wrong_type_are_malformed(server, annotations):
    tools = [TOOLS[0], {"name": "acme_odd", "description": "A tool with odd annotation values.", "inputSchema": {"type": "object"}, "annotations": annotations}]
    url, _ = server(tools=tools)
    result = next(r for r in check(url) if r.name == "Tool definitions")
    assert result.status == "FAIL" and "acme_odd" in result.detail


@pytest.mark.parametrize(("key", "value"), [("token_endpoint", "https://auth.example/token#frag"), ("authorization_endpoint", "https://auth.example/authorize#x")])
def test_oauth_endpoints_with_a_fragment_fail(server, key, value):
    url, _ = server(auth=True, metadata={key: value})
    assert statuses(check(url))["Authorization server metadata"] == "FAIL"


@pytest.mark.parametrize("issuer", ["https://auth.example/auth/v1#frag", "https://auth.example/auth/v1?tenant=a"])
def test_an_issuer_with_a_query_or_fragment_fails(server, issuer):
    url, _ = server(auth=True, issuer=issuer)
    assert statuses(check(url))["Authorization server metadata"] == "FAIL"


def test_a_public_handshake_is_found_even_when_the_token_breaks_it(server):
    url, _ = server(auth=True, public_handshake_only=True, handshake_rejects_token=True)
    results = statuses(check(url, token="good"))
    assert results["Token not needed"] == "INFO" and "Token accepted" not in results


def test_with_a_token_the_sign_in_metadata_is_still_checked(server):
    url, _ = server(auth=True, public={"server/discover", "initialize", "notifications/initialized"}, no_pkce=True)
    results = statuses(check(url, token="good"))
    assert results["Token accepted"] == "PASS" and results["Requires sign-in"] == "PASS"
    assert results["PKCE (S256)"] == "FAIL"


@pytest.mark.parametrize("kind", ["application/json-seq", "text/event-stream-invalid", "application/jsonx"])
def test_a_media_type_that_only_starts_like_json_or_sse_fails(server, kind):
    url, _ = server(content_type=kind)
    assert statuses(check(url))["Answers MCP requests"] == "FAIL"


def test_a_charset_parameter_is_fine(server):
    url, _ = server(content_type="application/json; charset=utf-8")
    assert statuses(check(url))["Lists tools"] == "PASS"


# --- Every combination of public and protected, over both protocols -------------------

_MATRIX = [
    {"md": md, "mt": mt, "hi": hi, "ht": ht}
    for md in (True, False)
    for mt in (True, False)
    for hi in (True, False)
    for ht in (True, False)
]


@pytest.mark.parametrize("token", [None, "good"])
@pytest.mark.parametrize("case", _MATRIX, ids=lambda c: "".join(k if v else "-" for k, v in c.items()))
def test_open_is_reported_exactly_when_some_protocol_lists_tools_without_a_token(server, monkeypatch, case, token):
    """md/mt: 2026-07-28 discover/tools public; hi/ht: handshake initialize/tools public."""
    pairs = set()
    if case["md"]:
        pairs.add(("modern", "server/discover"))
    if case["mt"]:
        pairs.add(("modern", "tools/list"))
    if case["hi"]:
        pairs.add(("handshake", "initialize"))
    if case["ht"]:
        pairs.add(("handshake", "tools/list"))
    url, _ = server(auth=True, open_pairs=pairs)
    results = check(url, token=token)
    named = statuses(results)
    # 2026-07-28 requests stand alone, so a public tools/list is enough; the handshake needs a session first.
    expected_open = case["mt"] or (case["hi"] and case["ht"])
    reported_open = "No sign-in required" in named
    assert reported_open == expected_open, [(r.status, r.name, r.detail) for r in results]
    if token and expected_open:
        assert "Token accepted" not in named
    if token and not expected_open:
        assert named.get("Token accepted") == "PASS", [(r.status, r.name, r.detail) for r in results]
    if not token and not expected_open:
        assert named.get("Requires sign-in") == "PASS", [(r.status, r.name, r.detail) for r in results]


def test_a_2026_only_shape_is_not_held_to_the_handshake_rules(server):
    tools = [TOOLS[0], {"name": "acme_list", "description": "Returns a list, which 2026-07-28 allows as output.", "inputSchema": {"type": "object"}, "outputSchema": {"type": "array"}}]
    url, _ = server(era="modern", tools=tools)
    assert "Tool definitions" not in statuses(check(url))


def test_a_stream_line_longer_than_one_read_is_joined(server, short_deadline):
    long_tool = {**TOOLS[0], "description": "Searches contacts. " + "x" * 100_000}
    url, _ = server(sse_open=True, tools=[long_tool])
    assert statuses(check(url))["Lists tools"] == "PASS"


# --- Codex's follow-ups from #17 (issue #25) -------------------------------------------

DISCOVER_PUBLIC = {"server/discover", "initialize", "notifications/initialized", "ping"}


def failures(results):
    return [(r.name, r.detail) for r in results if r.status == "FAIL"]


# 1. A recognized 2026-07-28 error is an answer from a 2026-07-28 server, not a reason to fall back.


@pytest.mark.parametrize(
    ("code", "name"),
    [(-32020, "HeaderMismatch"), (-32021, "MissingRequiredClientCapability"), (-32022, "UnsupportedProtocolVersion")],
)
@pytest.mark.parametrize("token", [None, "good"])
def test_a_recognized_2026_error_on_discover_fails_and_the_handshake_cannot_rescue_it(server, code, name, token):
    url, _ = server(auth=bool(token), discover_error={"code": code, "message": "rejected it"})
    results = check(url, token=token)
    refusal = next(r for r in results if r.name == "Protocol 2026-07-28")
    assert refusal.status == "FAIL"
    assert name in refusal.detail and str(code) in refusal.detail and "rejected it" in refusal.detail
    assert "don't fall back" in refusal.fix
    assert statuses(results)["Handshake protocol"] == "PASS"  # still reported, but it can't make the run pass
    assert report(results, lambda line: None) == 1


@pytest.mark.parametrize("code", [-32600, -32601, -32603, 5])
def test_any_other_error_on_discover_still_falls_back_to_the_handshake(server, code):
    url, _ = server(discover_error={"code": code, "message": "no such method"})
    results = check(url)
    assert statuses(results)["Protocol 2026-07-28"] == "INFO" and statuses(results)["Handshake protocol"] == "PASS"
    assert not failures(results)


@pytest.mark.parametrize("code", [[], {"a": 1}, "-32020", True, None, 1.5])
def test_an_error_code_that_is_not_an_integer_is_not_recognized(server, code):
    url, _ = server(discover_error={"code": code, "message": "odd"})
    assert statuses(check(url))["Protocol 2026-07-28"] == "INFO"


def test_the_recognized_error_is_reported_when_the_handshake_fails_too(server):
    url, _ = server(era="modern", discover_error={"code": -32020, "message": "rejected it"})
    results = check(url)
    assert statuses(results)["Protocol 2026-07-28"] == "FAIL"
    assert "Answers MCP requests" not in statuses(results)


# 2. A failed notifications/initialized fails the handshake.


@pytest.mark.parametrize("status", [401, 404, 500])
def test_a_failed_initialized_notification_fails_the_handshake(server, status):
    url, _ = server(initialized_status=status)
    results = check(url)
    handshake = next(r for r in results if r.name == "Handshake protocol")
    assert handshake.status == "FAIL" and "notifications/initialized" in handshake.detail and str(status) in handshake.detail
    assert report(results, lambda line: None) == 1


@pytest.mark.parametrize("status", [200, 202, 204])
def test_a_successful_initialized_notification_passes(server, status):
    url, _ = server(initialized_status=status)
    assert statuses(check(url))["Handshake protocol"] == "PASS"


def test_a_failed_initialized_notification_fails_the_signed_in_handshake_too(server):
    url, _ = server(auth=True, initialized_status=500)
    results = check(url, token="good")
    assert statuses(results)["Handshake protocol"] == "FAIL"
    assert statuses(results)["Protocol 2026-07-28"] == "PASS"


def test_an_anonymous_handshake_session_that_cannot_finish_setup_is_not_open(server):
    handshake = {("handshake", "initialize"), ("handshake", "tools/list")}
    url, _ = server(auth=True, open_pairs=handshake, initialized_status=500)
    named = statuses(check(url, token="good"))
    assert "Token not needed" not in named and "No sign-in required" not in named
    assert named["Token accepted"] == "PASS"


def test_an_anonymous_handshake_session_that_finishes_setup_is_open(server):
    handshake = {("handshake", "initialize"), ("handshake", "tools/list")}
    url, _ = server(auth=True, open_pairs=handshake)
    assert statuses(check(url, token="good"))["Token not needed"] == "INFO"


# 3. x-mcp-header on 2026-07-28 tool properties.

HEADER_SCHEMAS = [
    ("a valid header", {"region": {"type": "string", "x-mcp-header": "Region"}}, True),
    ("integer and boolean are allowed", {"n": {"type": "integer", "x-mcp-header": "N"}, "b": {"type": "boolean", "x-mcp-header": "B"}}, True),
    ("a nested object's property", {"o": {"type": "object", "properties": {"r": {"type": "string", "x-mcp-header": "R"}}}}, True),
    ("a name that isn't a token", {"region": {"type": "string", "x-mcp-header": "Re gion"}}, False),
    ("a name with a colon", {"region": {"type": "string", "x-mcp-header": "X:Y"}}, False),
    ("an empty name", {"region": {"type": "string", "x-mcp-header": ""}}, False),
    ("a name that isn't text", {"region": {"type": "string", "x-mcp-header": 5}}, False),
    ("a number property", {"price": {"type": "number", "x-mcp-header": "Price"}}, False),
    ("an object property", {"o": {"type": "object", "x-mcp-header": "O"}}, False),
    ("a list of types", {"region": {"type": ["string", "null"], "x-mcp-header": "Region"}}, False),
    ("no type", {"region": {"x-mcp-header": "Region"}}, False),
    ("a duplicate, ignoring case", {"a": {"type": "string", "x-mcp-header": "Region"}, "b": {"type": "string", "x-mcp-header": "region"}}, False),
    ("under anyOf", {"region": {"anyOf": [{"type": "string", "x-mcp-header": "Region"}]}}, False),
    ("under items", {"list": {"type": "array", "items": {"type": "string", "x-mcp-header": "Region"}}}, False),
    ("under additionalProperties", {"m": {"type": "object", "additionalProperties": {"type": "string", "x-mcp-header": "R"}}}, False),
]


def _tool_with(properties, **schema):
    return {**TOOLS[0], "name": "acme_regional", "inputSchema": {"type": "object", "properties": properties, **schema}}


@pytest.mark.parametrize(("label", "properties", "valid"), HEADER_SCHEMAS, ids=[c[0] for c in HEADER_SCHEMAS])
def test_x_mcp_header_rules_match_the_sdk(label, properties, valid):
    inbound = pytest.importorskip("mcp.shared.inbound")
    schema = {"type": "object", "properties": properties}
    assert (check_module._x_mcp_header_problem(schema) == "") is valid
    assert (inbound.find_invalid_x_mcp_header(schema) is None) is valid


def test_x_mcp_header_on_the_schema_root_is_invalid():
    inbound = pytest.importorskip("mcp.shared.inbound")
    schema = {"type": "object", "x-mcp-header": "Root", "properties": {}}
    assert check_module._x_mcp_header_problem(schema) and inbound.find_invalid_x_mcp_header(schema)


def test_x_mcp_header_rules_agree_with_the_sdk_on_random_schemas():
    inbound = pytest.importorskip("mcp.shared.inbound")
    rng = random.Random(25)
    names = ["Region", "region", "X-Id", "bad name", "", 5, None]
    kinds = ["string", "integer", "boolean", "number", "object", "array", ["string"], None, 7]

    def schema(depth=0):
        node = {}
        if rng.random() < 0.8:
            node["type"] = rng.choice(kinds)
        if rng.random() < 0.5:
            node["x-mcp-header"] = rng.choice(names)
        if depth < 3:
            if rng.random() < 0.4:
                node["properties"] = {f"p{i}": schema(depth + 1) for i in range(rng.randint(0, 3))}
            for keyword in rng.sample(["items", "anyOf", "additionalProperties", "not", "$defs"], rng.randint(0, 2)):
                inner = schema(depth + 1)
                node[keyword] = [inner] if keyword == "anyOf" else {"k": inner} if keyword == "$defs" else inner
        return node

    for i in range(400):
        candidate = schema()
        ours = check_module._x_mcp_header_problem(candidate) == ""
        assert ours == (inbound.find_invalid_x_mcp_header(candidate) is None), (i, candidate)


def test_a_tool_with_an_invalid_x_mcp_header_fails_over_2026(server):
    bad = _tool_with({"price": {"type": "number", "x-mcp-header": "Price"}})
    url, _ = server(era="modern", tools=[TOOLS[0], bad])
    result = next(r for r in check(url) if r.name == "Tool definitions")
    assert result.status == "FAIL" and "acme_regional" in result.detail and "price" in result.detail


def test_a_tool_with_a_valid_x_mcp_header_passes_over_2026(server):
    good = _tool_with({"region": {"type": "string", "description": "Where", "x-mcp-header": "Region"}})
    url, _ = server(era="modern", tools=[TOOLS[0], good])
    assert "Tool definitions" not in statuses(check(url))


def test_x_mcp_header_is_only_judged_over_2026(server):
    bad = _tool_with({"price": {"type": "number", "x-mcp-header": "Price"}})
    url, _ = server(era="legacy", tools=[TOOLS[0], bad])
    assert "Tool definitions" not in statuses(check(url))


def test_a_real_sdk_server_with_an_x_mcp_header_tool_passes():
    srv, url = _sdk_server(header_tool=True)
    try:
        results = check(url)
    finally:
        srv.should_exit = True
    assert not failures(results), failures(results)
    assert statuses(results)["Lists tools"] == "PASS"


# 4. A 403 without a token isn't sign-in.

SIGN_IN_FIX = "401 and a WWW-Authenticate challenge"


def test_a_403_for_tools_without_a_token_is_not_sign_in(server):
    url, _ = server(auth=True, deny_status=403, public=DISCOVER_PUBLIC)
    results = check(url)
    sign_in = next(r for r in results if r.name == "Requires sign-in")
    assert sign_in.status == "FAIL" and "403" in sign_in.detail and SIGN_IN_FIX in sign_in.fix
    assert report(results, lambda line: None) == 1


def test_a_403_for_every_request_without_a_token_is_not_sign_in(server):
    url, _ = server(auth=True, deny_status=403)
    results = check(url)
    sign_in = next(r for r in results if r.name == "Requires sign-in")
    assert sign_in.status == "FAIL" and SIGN_IN_FIX in sign_in.fix
    assert "Answers MCP requests" not in statuses(results)


def test_a_401_for_tools_without_a_token_is_still_sign_in(server):
    url, _ = server(auth=True, public=DISCOVER_PUBLIC)
    assert statuses(check(url))["Requires sign-in"] == "PASS"


def test_a_403_with_a_token_is_still_a_rejected_token(server):
    url, _ = server(auth=True, deny_status=403)
    assert statuses(check(url, token="bad"))["Token accepted"] == "FAIL"


# 5. resource_metadata counts only on a Bearer challenge.


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ('Bearer error="x", resource_metadata="u"', [("bearer", {"error": "x", "resource_metadata": "u"})]),
        ('Basic realm="x", Foo resource_metadata="u"', [("basic", {"realm": "x"}), ("foo", {"resource_metadata": "u"})]),
        ("Bearer", [("bearer", {})]),
        ("Negotiate abc123==", [("negotiate", {})]),
        ('bEARER Resource_Metadata = "u"', [("bearer", {"resource_metadata": "u"})]),
        ('Bearer realm="a\\"b, c", resource_metadata=u', [("bearer", {"realm": 'a"b, c', "resource_metadata": "u"})]),
        ("Bearer resource_metadata=http://h:1/p?q=1", [("bearer", {"resource_metadata": "http://h:1/p?q=1"})]),
        ('Bearer a="1", a="2"', [("bearer", {"a": "1"})]),
        ("", []),
        (",,, ,", []),
        ('realm="x"', []),
        ('Bearer a="unterminated, b=c', [("bearer", {"a": "unterminated, b=c"})]),
    ],
)
def test_www_authenticate_is_read_as_challenges(header, expected):
    assert check_module._challenges(header) == expected


@pytest.mark.parametrize(
    ("challenge", "status"),
    [
        ('Basic realm="x", Foo resource_metadata="{link}"', "WARN"),
        ('Foo resource_metadata="{link}", Bearer error="invalid_token"', "WARN"),
        ('Basic resource_metadata="{link}"', "WARN"),
        ('Bearer error_description="resource_metadata={link}"', "WARN"),
        ('bearer RESOURCE_METADATA="{link}"', "PASS"),
        ('BEARER resource_metadata="{link}"', "PASS"),
        ('Basic realm="x", Bearer resource_metadata="{link}"', "PASS"),
        ('Bearer error_description="a, resource_metadata=nope", resource_metadata="{link}"', "PASS"),
    ],
)
def test_the_metadata_link_counts_only_on_a_bearer_challenge(server, challenge, status):
    url, _ = server(auth=True, challenge=challenge)
    results = statuses(check(url))
    assert results["401 points to sign-in"] == status
    assert results["Protected resource metadata"] == "PASS"  # the well-known address still finds it


def test_a_non_bearer_challenge_is_explained(server):
    url, _ = server(auth=True, challenge='Basic realm="x", Foo resource_metadata="{link}"')
    warning = next(r for r in check(url) if r.name == "401 points to sign-in")
    assert "Bearer" in warning.detail and "Bearer" in warning.fix


# Fuzzing: real servers on localhost whose replies are sometimes spoiled on the wire.

FUZZ_RUNS = int(os.environ.get("FUZZ_RUNS", "100"))
_JUNK = [None, True, False, 0, -1, 2**70, 1.5, "", "x" * 50, [], {}, [1, "a"], {"a": None}, "\u0000é"]
_CHALLENGES = [
    'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"',
    'Bearer resource_metadata={base}/.well-known/oauth-protected-resource/mcp, error="invalid_token"',
    'Basic realm="x"',
    "Bearer",
    "",
    '"',
    "Bearer ,,, =",
    "Bearer resource_metadata=",
    'Bearer a="b',
    "=" * 500,
    'Foo resource_metadata="{base}/x", Bearer',
    'Bearer resource_metadata="javascript:alert(1)"',
    'Bearer resource_metadata="//x"',
]
_PROFILES = [
    {},
    {"auth": True},
    {"auth": True, "public": {"server/discover", "ping"}},
    {"auth": True, "deny_status": 403},
    {"auth": True, "unquoted": True},
    {"auth": True, "challenge": 'Basic realm="x", Bearer resource_metadata="{link}"'},
    {"era": "legacy"},
    {"era": "modern"},
    {"sse": True},
    {"pages": [TOOLS, TOOLS]},
    {"initialized_status": 500},
    {"discover_error": {"code": -32020, "message": "mismatch"}},
    {"tools": [{"name": "t", "description": "A tool that does one thing.", "inputSchema": {"type": "object", "properties": {"q": {"type": "number", "x-mcp-header": "Q"}}}}]},
]
DEEP = {"Lists tools", "Tool definitions", "Handshake protocol", "Authorization server metadata", "Requires sign-in"}  # what a fuzz run must reach


def _mutate(rng, value, depth=0):
    if depth > 6 or rng.random() < 0.12:
        return rng.choice(_JUNK)
    if isinstance(value, dict):
        kept = {k: _mutate(rng, v, depth + 1) for k, v in value.items() if rng.random() > 0.1}
        if rng.random() < 0.1:
            kept[rng.choice(["x-mcp-header", "type", "properties", "code"])] = rng.choice(_JUNK)
        return kept
    if isinstance(value, list):
        return [_mutate(rng, v, depth + 1) for v in value]
    return value


def _spoiling_proxy(upstream_port, rng, rate):
    """A server that passes each request to a good one and, now and then, spoils the reply on the wire."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def handle_any(self):
            port = self.server.server_port
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            try:
                upstream = http.client.HTTPConnection("127.0.0.1", upstream_port, timeout=10)
                sent = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "connection")}
                upstream.request(self.command, self.path, raw or None, sent)
                reply = upstream.getresponse()
                status, body = reply.status, reply.read()
                headers = [(k, v) for k, v in reply.getheaders() if k.lower() not in ("content-length", "transfer-encoding", "connection")]
                upstream.close()
            except OSError:
                return

            def mine(data):  # links in the reply name the good server; they should name this one
                return data.replace(f"127.0.0.1:{upstream_port}".encode(), f"127.0.0.1:{port}".encode())

            body, headers, lie = mine(body), [(k, mine(v.encode()).decode()) for k, v in headers], 0
            here = f"http://127.0.0.1:{port}"
            if rng.random() < rate:
                for spoil in rng.sample(["hangup", "status", "type", "challenge", "session", "location", "json", "cut", "garbage", "sse", "big", "lie"], rng.randint(1, 3)):
                    if spoil == "hangup":
                        return
                    if spoil == "status":
                        status = rng.choice([200, 201, 202, 204, 301, 302, 307, 400, 401, 403, 404, 405, 500, 503, 99, 600])
                    elif spoil == "type":
                        kind = rng.choice(["application/json", "text/event-stream", "text/plain", "application/json; charset=utf-8", "", "\x01", "application/jsonx"])
                        headers = [("Content-Type", kind), *[(k, v) for k, v in headers if k.lower() != "content-type"]]
                    elif spoil == "challenge":
                        headers.append(("WWW-Authenticate", rng.choice(_CHALLENGES).format(base=here, link=here)))
                    elif spoil == "session":
                        headers.append(("Mcp-Session-Id", rng.choice(["abc", "", "a b", "\x7f", "é", "x" * 5000])))
                    elif spoil == "location":
                        headers.append(("Location", rng.choice([f"{here}/mcp", "https://other.example/", "", "//x", "http://[bad"])))
                    elif spoil == "json":
                        try:
                            body = json.dumps(_mutate(rng, json.loads(body))).encode()
                        except ValueError:
                            pass
                    elif spoil == "cut":
                        body = body[: rng.randint(0, len(body))]
                    elif spoil == "garbage":
                        body = bytes(rng.randrange(256) for _ in range(rng.randint(0, 200)))
                    elif spoil == "sse":
                        body = b"data: " + body + rng.choice([b"\n\n", b"\n", b"", b"\r\n\r\n"])
                        headers = [("Content-Type", "text/event-stream"), *[(k, v) for k, v in headers if k.lower() != "content-type"]]
                    elif spoil == "big":
                        body = b"x" * 100_000
                    elif spoil == "lie":
                        lie = rng.choice([10, -len(body)])
            head = f"HTTP/1.0 {status} X\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers) + f"Content-Length: {max(len(body) + lie, 0)}\r\n\r\n"
            try:
                self.wfile.write(head.encode("latin-1", "replace") + body)
            except OSError:
                pass

        do_GET = do_POST = handle_any

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def test_random_malformed_replies_never_crash_the_check(short_deadline):
    """FUZZ_RUNS=5000 runs it much longer; a failure names its seed, which replays it."""
    reached = set()
    for seed in range(FUZZ_RUNS):
        rng = random.Random(seed)
        options = rng.choice(_PROFILES)
        good, _, _ = serve(**options)
        proxy = _spoiling_proxy(good.server_port, rng, rate=rng.choice([0, 0.05, 0.15, 0.4]))
        threading.Thread(target=proxy.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        token = rng.choice([None, "good", "t0k3n-secret"])
        try:
            results = check(f"http://127.0.0.1:{proxy.server_port}/mcp", token=token)
            lines = []
            report(results, lines.append)
        except Exception as exc:
            raise AssertionError(f"check() raised for seed {seed} ({options}, token {token})") from exc
        finally:
            for srv in (proxy, good):
                srv.shutdown()
                srv.server_close()
        assert results and all(r.status in ("PASS", "WARN", "FAIL", "INFO") for r in results), seed
        assert not any("t0k3n-secret" in line for line in lines), seed
        reached |= {r.name for r in results}
    if FUZZ_RUNS >= 100:  # a fuzzer that stops at the first reply proves nothing
        assert DEEP <= reached, DEEP - reached
