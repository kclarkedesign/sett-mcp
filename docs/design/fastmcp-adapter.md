# Sett for FastMCP: adapter plan

**Status:** plan; the spike is done (2026-11-11, **go**) and nothing else is built. Researched 2026-11-08 against Sett `main` at v0.3.2 (GitHub) and FastMCP 4.1.6; the spike ran on FastMCP 4.1.8.
**TL;DR:** ship a separate `sett-fastmcp` package, kept in the sett-mcp repo, whose core is one `SettMiddleware` added with `mcp.add_middleware(...)`. It reads the same YAML policy through code shared with the template. FastMCP 4 runs on the same official SDK v2 as Sett (`mcp>=2.3,<3`), so the policy core can be shared directly. The hard part is confirmations. They have to work on both protocol versions: the 2026-07-28 guard pattern (multi-round-trip requests) and the older `ctx.elicit()`, because FastMCP has no equivalent of the SDK's `Resolve`. A spike confirmed that middleware can run the new-protocol confirmation itself (see "Spike results").

---

## Review and decisions (2026-11-08)

The plan was reviewed against Sett's code and this week's real-client testing. The recommendation stands: **Option A, a `SettMiddleware` in a separate `sett-fastmcp` package in this repo, with a shared `policy.py` and a drift check.** Additions and answers:

- **Release tags must not collide.** `sett-mcp` now takes its version from `v*` tags only (`tag_regex` and `git describe --match v[0-9]*` in `pyproject.toml`). `sett-fastmcp` uses `sett-fastmcp-v*` tags with the opposite rule. Copier ignores tags that aren't plain versions, so the template's "latest release" stays the latest `v*`.
- **Real-client lessons to carry over:**
  - The confirmation form schema holds only `type`/`properties` (Codex rejects a top-level `title`).
  - A cancel is never reported as a decline.
  - Claude Desktop's local bridge drops prompts, so the refusal path must be clear and tested.
  - The FastMCP column in the client support table needs the same real-client pass: Claude Code, claude.ai, Claude Desktop, Cursor and Codex, local and remote.
- **`check(mcp)` and `sett-mcp check <url>`:** the in-process `check()` here covers policy wiring. The CLI `sett-mcp check` already tests a deployed FastMCP server's sign-in setup and tool hints from outside, so the docs should point FastMCP users to both.
- **Effort estimate:** the spike takes half a day, the `policy.py` extraction about half a day, and the middleware plus the parity tests 2 to 3 days. Docs, the client pass and the release take about a day.

Answers to section 10:

1. **Proxied tools:** distrust upstream annotations by default; opt in with `trust_proxy_annotations=True`.
2. **Tools you can't annotate:** wait for a real request; use `allow` lists meanwhile.
3. **HTTP without a shared key:** yes, `check(mcp)` warns when confirmations are on and the request-state key is per-process.
4. **Writer role:** a callable only in v1. Move `StderrAuditSink` and `SupabaseAuditSink` into `policy.py`; they need only the standard library and `anyio`. Keep `jwt` in `remote.py`.
5. **FastMCP 3.x:** no.
6. **Where this lives:** here, `docs/design/fastmcp-adapter.md`, versioned with the code. The roadmap links to it.
7. **Replay within the TTL (decided 2026-11-11):** document it, and recommend `RequestStateSecurity(ttl=120)` in the README for servers with non-idempotent writes. Whether `check(mcp)` can read the server's TTL to warn about a long one is untested, so don't promise it.

---

## Spike results (2026-11-11)

**Go.** FastMCP 4's middleware can run Sett's confirmation on both protocol versions, so Option A stands and the §4 fallback is not needed. Code and raw output: [`spikes/fastmcp-middleware/`](../../spikes/fastmcp-middleware/) (`spike.py`, `last-run.txt`, `RESULTS.md`). Tested on fastmcp 4.1.8 and mcp 2.3.0, Python 3.14 only.

| Question | Answer |
|---|---|
| **8a** Can middleware return `InputRequiredToolResult`? | Yes. The round trip completes with `Client(mode="auto")`: two middleware rounds, handler called once, the tool ran only after `accept`. `decline` and `cancel` ran nothing and reported distinct messages. The old protocol works from the same middleware. |
| **8b** How to read client capabilities? | `ctx.session.client_capabilities`, on both eras (per request on 2026-07-28). Check for *form* support **up front** on both (§4 has the exact test: presence of `elicitation` alone isn't enough, since a URL-only client has it set). Without a check, a client with no handler fails safe but with its own raw `MCPError: Elicitation not supported` and no audit entry. |
| **8c** Empty form on the old protocol? | Don't use `ctx.elicit()`: an empty dataclass or model sends a top-level `title`, which Codex rejects. Use `await ctx.session.elicit_form(message, {"type": "object", "properties": {}})`. |
| **8d** Does the SDK already bind the confirmation? | Yes: it seals `(tool, args digest, principal)` plus a TTL (600 s) and audience into `request_state`, and refuses a replay with other arguments. It does **not** refuse an accept that carries no state, so the middleware must require its marker. It does **not** make a state single-use either (risk 9). |

---

## 1. Context

Sett's guardrails live in `template/src/{{package_name}}/guardrails.py`. They are applied by **registering** tools through `guard.read` / `guard.write` on the SDK's `MCPServer`:

- write gate (`<PREFIX>_ENABLE_WRITES`)
- allow/deny lists
- confirmations (`destructive` / `all_writes` / `off`), with distinct `declined` / `cancelled` / `blocked` outcomes
- masking, plus refusing writes that carry the `[masked]` placeholder
- JSONL audit log plus `AuditSink`s
- `writer_check` in remote mode

FastMCP users can't adopt any of this today. Their tools come from `@mcp.tool`, mounted servers, proxies and OpenAPI providers, none of which go through Sett's decorators. **Goal:** a FastMCP user gets the same policy file and the same observable behavior: the same tools visible, the same prompts, the same refusal text, the same audit entries.

## 2. What FastMCP looks like today (research summary)

| Fact | Evidence |
|---|---|
| The current major is **4.x**: 4.1.6 released 2026-11-03, 4.0.0 on 2026-08-31, 3.0.0 on 2026-02-18. 3.x is still maintained (3.4.11). The repo moved from `jlowin/fastmcp` to **`PrefectHQ/fastmcp`**. | [PyPI][pypi], [v4.0.0 notes][v4] |
| It depends on **`mcp>=2.3.0,<3`** and `mcp-types>=2,<3`, the same SDK as Sett. `fastmcp` is now a wrapper over `fastmcp-slim`. | [fastmcp_slim/pyproject.toml][slim] |
| Middleware: `from fastmcp.server.middleware import Middleware, MiddlewareContext`. `on_list_tools` gets and returns `Sequence[Tool]`, so it can filter. `on_call_tool` returns `ToolResult` (`content`, `structured_content`, `meta`, `is_error`). It runs **before** the tool is looked up. Registration is `mcp.add_middleware()` or `FastMCP(middleware=[...])`, and the first one added runs outermost. | [middleware docs][mw], [middleware.py][mwsrc] |
| Parent middleware runs for mounted servers. The source shows proxy and OpenAPI tools also go through `FastMCP.call_tool`, and with it the middleware chain. Proxy tools copy their upstream `annotations`, `meta` and tags. | [composition][comp], [mw docs][mw] |
| `@mcp.tool(annotations=..., meta=..., tags=..., auth=...)`. Annotations are SDK v2 snake_case (`read_only_hint`). The camelCase names still work but warn. `get_tool()` returns `None` for a missing, disabled or unauthorized tool. | [upgrade guide][up3] |
| **`ctx.elicit()` only works on old-protocol connections.** On 2026-07-28 connections a tool must *return* an `InputRequiredResult`. The answers come back in `ctx.input_responses`, and FastMCP seals `ctx.request_state` (shared key: `FastMCP(request_state_security=RequestStateSecurity(keys=[...]))`). Every round "runs the full request path — middleware chain included". | [elicitation docs][elic], [v4 notes][v4] |
| The wire handler unwraps any `InputRequiredToolResult` that comes out of `self.call_tool()`, which is the middleware chain. So **middleware returning one works**: read from source, then confirmed by the spike (2026-11-11). | [mcp_operations.py][ops], [tools/base.py][toolbase] |
| `response_type=None` was removed in 4.0 ("use `bool`"). Scalars get wrapped as `{"value": ...}`. | [upgrade guide][up3] |
| Old-protocol `ctx.elicit` fails under `stateless_http` or `json_response` (`NoBackChannelError`), and legacy sessions live in a per-process dict, so they need sticky routing. | [SDK legacy-clients][legacy], [FastMCP HTTP deploy][http] |
| Auth: `fastmcp.server.auth` provides `JWTVerifier`, `RemoteAuthProvider`, `OAuthProxy`, Supabase and other providers, `require_scopes`, `require_roles` (4.0) and `AuthMiddleware` (which skips stdio). Read the token with `fastmcp.server.dependencies.get_access_token()`. | [authorization][authz] |
| Visibility: `mcp.disable(names=/tags=)`. A disabled tool "disappears from listings and cannot be called." | [visibility][vis] |
| Testing: `async with Client(mcp, mode="auto"\|"legacy", elicitation_handler=...)`. The client drives multi-round-trip rounds itself. With no handler, it does not advertise elicitation. | [testing][test], [elicitation][elic] |
| Pitfall: `DeclinedElicitation` and `CancelledElicitation` are truthy (open issue #4929). Check `action == "accept"`. | [#4929][i4929] |
| Spec: `readOnlyHint` defaults to false and `destructiveHint` to **true**. Clients "MUST consider tool annotations to be untrusted unless they come from trusted servers." | [spec tools][spectools], [schema.ts][schema] |
| Prior art: Eunomia (`eunomia-mcp`) and `permit-fastmcp` both filter lists and block calls in middleware, but they are pinned to `fastmcp>=2.10` and inactive since late 2025. FastMCP's own `Approval` provider is "advisory … not an enforcement mechanism." Nobody ships enforced confirmations or masking for FastMCP 4. | [Eunomia][eunomia], [Permit][permit], [Approval][approval] |

## 3. Options

### A. Middleware adapter (`SettMiddleware`)
One middleware enforces everything on the request path:
- `on_list_tools` hides tools the policy rules out.
- `on_call_tool` blocks hidden tools, checks writer and placeholder, confirms, audits and masks.
- Tool kind comes from annotations. Missing annotations fall back to the spec defaults: **destructive write**.

### B. Decorator wrapper (`guard.read/write` over `mcp.tool`)
A port of today's API. The wrapper registers the tool only when the policy allows it, and its body runs the guard round or `ctx.elicit`, masks and audits.

### C. Native-only (Visibility + `AuthMiddleware` + transforms)
`mcp.disable(...)` at startup handles the gate and `require_roles` handles the writer role. **Rejected:** FastMCP has no native confirmation, masking or audit, and `ToolTransform` is per-name, so it can't wrap every tool ([tool transformation][tt]).

| | A. Middleware | B. Decorator |
|---|---|---|
| **Coverage** | Every tool: local, mounted, proxied, OpenAPI | Only tools written with `guard.*`. Mounts, proxies and OpenAPI tools are unguarded |
| **A tool someone forgot to mark** | Treated as a destructive write: hidden unless writes are on, and confirmed | A plain `@mcp.tool` bypasses everything (today's template guards against this only with a `CLAUDE.md` rule) |
| **Write gate** | Hidden from lists and blocked on call (answers "Unknown tool", like an unregistered tool) | Truly unregistered (strongest) |
| **Confirmation** | Era branch in one place; no signature surgery | Same era branch, plus `ctx: Context` injected into each wrapped signature |
| **Masking** | On the serialized `ToolResult` (structured content plus JSON text blocks) | On the Python return value (as today) |
| **Adoption** | One line in an existing server, plus annotations | Rewrite every tool definition |
| **`confirm_message` check** | `check(mcp)` at startup or in tests | Fails at decoration time (as today) |

## 4. Recommendation

**Option A: middleware as the only enforcement layer, with no decorator sugar in v1.** Annotations and `meta` are native FastMCP, so a helper decorator would be a second API to maintain.

It wins on what makes Sett *Sett*. Safe-by-default has to cover tools nobody remembered to mark, and in FastMCP those are often mounted, proxied or generated tools, which only middleware sees. The decorator's one advantage, true non-registration, buys little when the middleware also blocks the call and answers exactly as for an unknown tool.

**Fallback** (not needed: the spike passed): keep the gate, masking and audit in middleware, and move only the 2026-07-28 confirmation into a small per-tool wrapper.

### Developer-facing API
```python
from fastmcp import FastMCP
from mcp.server.request_state import RequestStateSecurity
from mcp_types import ToolAnnotations
from sett_fastmcp import Policy, SettMiddleware

mcp = FastMCP("Acme", request_state_security=RequestStateSecurity(keys=[KEY]))  # key needed only for multiple instances
mcp.add_middleware(SettMiddleware(Policy.load("ACME")))   # add FIRST so it is outermost

@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
def acme_search_contacts(query: str) -> list[dict]: ...

@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
          meta={"sett": {"confirm_message": "Permanently delete contact {contact_id}?"}})
def acme_delete_contact(contact_id: str) -> dict: ...
```

### Middleware outline (about 200 lines)
- **`kind(tool)`:**
  - Returns `read` if `read_only_hint` is set.
  - Returns `write` if `destructive_hint is False`.
  - Otherwise returns `destructive`, the spec defaults.
  - Proxy tools (`ProxyTool`) are always treated as `destructive` unless the constructor sets `trust_proxy_annotations=True`, because their hints come from an untrusted upstream.
- **`visible(tool)`:** `policy.permits(name) and (kind == "read" or policy.writes_enabled)`.
- **`on_list_tools`:** filters with `visible`, then fills in any missing annotations explicitly. That way clients still see hints on every tool, which matches Sett's "every tool is marked" guarantee.
- **`on_call_tool`:**
  1. Look up the tool. If it is `None` or not visible, raise `NotFoundError` (the same "Unknown tool" answer).
  2. For writes: run the writer check (`writer_check(get_access_token())`), then the placeholder check. Both use shared refusal text.
  3. If confirmation is needed:
     - **Capability check, both eras, before anything else:** read `ctx.session.client_capabilities` and test for *form* support: `e = caps.elicitation if caps else None`, then `e is not None and (e.form is not None or e.url is None)`. A client that declares only `url` can't show our form, while an empty `elicitation: {}` counts as form (the spec's backward-compatibility rule). If the test fails, audit `blocked` and raise `ToolError` "can't carry a confirmation prompt". Don't use the SDK's `check_client_capability` for this: it only checks that `elicitation` is present, so it lets a URL-only client through (`spikes/fastmcp-middleware/capabilities.py`). The spike showed that without any check a modern client with no handler gets its own raw `MCPError` and no audit entry.
     - **2026-07-28:** if `ctx.input_responses["sett_confirm"]` is present and `ctx.request_state == MARKER`, read its `action`. If responses arrive without the marker, refuse: that is a forged accept, and the SDK doesn't catch it. Otherwise return `InputRequiredToolResult(InputRequiredResult(input_requests={"sett_confirm": ElicitRequest(form, empty schema)}, request_state=MARKER))`. The asking round writes no audit entry, matching Sett.
     - **Older protocol:** send the form with `ctx.session.elicit_form(text, {"type": "object", "properties": {}})`, not `ctx.elicit(...)`, which adds a top-level `title` that Codex rejects (spike 8c).
     - Then: `accept` runs the tool, `decline` raises `ToolError` "declined", `cancel` raises "cancelled", each with an audit entry.
  4. Time `call_next`, audit `ok` or `error`, then mask `structured_content` and every JSON `TextContent`. Never mask an `InputRequiredToolResult`.
- **`MARKER`:** a constant string, for example `"sett-confirm-v1"`. The SDK already seals `(tool, args digest, principal)` plus a TTL and audience into `request_state`, as the spec says servers SHOULD ([MRTR][mrtr]), so a confirmation for `delete c1` can't be replayed for `delete c2` (spike 8d). The marker's only job is to refuse an "accept" that arrives with no state, which the SDK lets through.
- **`check(mcp)`:** an async helper for startup and tests. It lists tools, validates `confirm_message` placeholders against each tool's parameters (raising `ValueError`, as Sett does), and logs which tools are visible versus hidden.

## 5. What's shared with `guardrails.py` and what's reimplemented

| Piece | Today | Plan |
|---|---|---|
| `Policy`, `_PolicyFile` (`extra="forbid"`), `PolicyError`, `load`/`from_yaml`/`permits`, `_TRUTHY` | `guardrails.py` | **Shared verbatim** |
| `MASK`, `mask()`, `_holds_mask()` | `guardrails.py` | **Shared** |
| Confirmation prompt text (`confirm_message.format`; generic `Allow tool(k=v)?`, masked, unset values skipped) | inline in `resolver` | **Extract `confirm_text()` and share it** |
| Refusal messages (blocked / cancelled / declined / forbidden / placeholder) | inline strings | **Extract and share**, so error text is identical |
| Audit entry, JSONL write that fails open, `AuditSink` protocol, sink fan-out | `Guardrails._audit` | **Extract an `Audit` class and share it.** The caller passes `subject`/`client_id`, because each framework reads the token differently |
| Empty form schema (no `title`; Codex rejects one) | `Confirmation` model | **Share as a plain dict**, sent with `ctx.session.elicit_form` (spike 8c: `ctx.elicit` adds a `title`) |
| Registration, `Resolve`/`Elicit` signature synthesis, worker-thread sync tools | `Guardrails.read/write` | SDK only. FastMCP already runs sync tools in a threadpool |
| Annotation-based kind, list filtering, era-branch confirmation, request-state binding, `ToolResult` masking | — | FastMCP only (`middleware.py`) |
| `remote.py` (`JWTVerifier`, `RemoteSettings`), `deploy.py`, `consent.py`, installer | template | **Not ported.** FastMCP's own auth providers replace the verifier. Sett's `StderrAuditSink` and `SupabaseAuditSink` work unchanged as sinks (see open question 4) |

**How it's shared:** move the framework-free pieces into a new `template/src/{{package_name}}/policy.py`. It has no Jinja and no `mcp` imports. `guardrails.py` imports and re-exports it, so the template's tests stay unchanged. `sett-fastmcp` keeps a **byte-identical copy** at `src/sett_fastmcp/_policy.py`, and a CI job fails on any diff.

- **Why copy instead of a `sett-core` package:** template users keep owning their guardrail code, and `copier update` keeps working.
- **Limit:** if a third adapter ever appears, promote the copy to a `sett-core` package.

## 6. Package and repo layout

**Recommendation: a separate PyPI package `sett-fastmcp`, in the sett-mcp repo. No template option in v1.**

- **Package over template option:** most FastMCP users have an existing server, and Copier can't retrofit one. A `framework: fastmcp` question would also add `{% if %}` branches to every template file and double the CI matrix. Add it later only if people ask for it; it would just depend on this package.
- **Not an extra on `sett-mcp`:** that package is the Copier CLI and would pull `copier` into every FastMCP server.
- **Same repo:** one policy schema, a local drift check, one issue tracker, one client-support table.

```
sett-mcp/
├─ template/src/{{package_name}}/
│  ├─ policy.py            NEW: framework-free core (single source of truth)
│  └─ guardrails.py        imports from .policy; re-exports Policy, PolicyError, MASK
├─ packages/sett-fastmcp/
│  ├─ pyproject.toml       sett-fastmcp; deps: fastmcp>=4.1,<5, pyyaml>=6; dev: pytest, anyio
│  ├─ README.md            quick start, annotation rules, multi-instance key, short `ttl` advice, gaps
│  ├─ src/sett_fastmcp/
│  │  ├─ __init__.py       Policy, PolicyError, MASK, AuditSink, SettMiddleware, check
│  │  ├─ _policy.py        copy of template policy.py (CI-enforced)
│  │  └─ middleware.py
│  └─ tests/{conftest.py, test_middleware.py}
└─ .github/workflows/
   ├─ test-template.yml     + "policy.py copy unchanged" step (diff)
   ├─ test-sett-fastmcp.yml NEW
   └─ publish.yml           + sett-fastmcp on tag prefix sett-fastmcp-v*
```

## 7. Test strategy (FastMCP in-memory client)

Port `template/tests/test_guardrails.py.jinja` assertion for assertion. Use `fastmcp.Client(mcp, mode=..., elicitation_handler=...)`, with the same contacts fixture declared as FastMCP tools. Run confirmation tests on **both eras**: `mode="auto"` (guard rounds) and `mode="legacy"` (`ctx.elicit`).

**Parity tests** (same names as the template's):
- writes hidden by default / visible when enabled
- deny and allow lists
- hints present
- confirm, decline and cancel (cancel is never reported as a decline)
- form schema keys limited to `{$schema, type, properties, required}`
- refused when the client can't confirm, on both eras (capability checked up front)
- `confirm: off` and `all_writes`
- placeholder refused without asking
- generic prompt lists only the arguments given
- masking in `structured_content` and in text
- audit outcomes with masked arguments
- policy strictness and the env-only write switch

**FastMCP-specific tests:**
1. An un-annotated tool is treated as destructive: hidden when writes are off, confirmed when on.
2. Calling a hidden tool returns "Unknown tool", the same as a nonexistent one.
3. Tools on a mounted child server are gated and masked. Allow/deny match the **namespaced** names clients see.
4. Tools from `create_proxy(...)` are treated as destructive even when upstream says `read_only_hint=True`, unless trust is opted into.
5. A forged first round (`inputResponses` with accept and no request state) is **refused** and doesn't run. The SDK lets it through, so this is our own check (spike 8d).
6. Request state from a call with different arguments is refused, and the tool doesn't run. The SDK does this itself (spike 8d), so this is a regression test.
7. **Multiple instances:** two `FastMCP` servers share one `RequestStateSecurity` key. Round 1 goes to A and round 2 to B with the sealed state, and the tool runs. With different keys it's refused. This drives raw rounds through the SDK v2 client, as Sett's `test_http` does.
8. Tools reached through other paths still go through the middleware: a tool called from another tool, and a search/code-mode transform if FastMCP ships one.
9. Ordering: with `ResponseCachingMiddleware` added after Sett, a hidden write is never served from cache.
10. `writer_check` with a `StaticTokenVerifier` token: a reader is `forbidden`, a writer is allowed, and the audit entry carries `subject` and `client_id`.
11. `check(mcp)` raises on an unknown `confirm_message` placeholder.
12. A genuine confirmation state used a second time: the SDK doesn't refuse it (spike 8d). Pin the documented behavior (open question 7): a state can be used again within its TTL.
13. Capability matrix for the up-front check: no `elicitation` (blocked), `elicitation: {}` (allowed: form by the backward-compatibility rule), `form` only (allowed), `url` only (blocked), `form` and `url` (allowed). The predicate is already checked against the SDK's capability models in `spikes/fastmcp-middleware/capabilities.py`; the real test should also drive a URL-only client end to end, which the spike did not.

**CI:**
- matrix of Python 3.10/3.13 × fastmcp `4.1.*` (floor) and latest. fastmcp 4.1.8 and `mcp` 2.3.0 declare `Requires-Python >=3.10`, but the spike ran on 3.14 only
- a weekly scheduled run with prereleases allowed, to catch 4.2 and 5.0 early (FastMCP has shipped a major roughly every six months)
- the drift check
- **Real-client smoke test** (manual, before release): Claude Code, Cursor, Codex and claude.ai on a FastMCP sample server. Record the results in a FastMCP column of the client-support table.

## 8. Gaps and risks

1. **No era-portable confirmation.** The SDK's `Resolve(...)` covers both protocol versions in one mechanism. FastMCP "has no resolver injection", so the adapter keeps two paths and tests both.
2. **Old-protocol confirmations need a stateful session.** They fail under stateless HTTP and on unpinned replicas. This is the same limit as Sett today; map that failure to the `blocked` refusal, never to a crash or an allow.
3. **Confirmations across instances.** On 2026-07-28 this works with a shared `request_state_security` key, the same model as Sett's `<PREFIX>_REQUEST_STATE_KEY`. The middleware can't tell whether you run more than one instance, so a missing key fails as "refused" on another replica. It fails safe, but confusingly. See open question 3.
4. **Annotations are hints.** Local ones are trusted because the server author wrote them. Proxied ones are not (spec). The default is to distrust proxies. OpenAPI tools carry no hints, so they all become destructive writes; that's safe but noisy (see open question 2).
5. **Masking happens after serialization.** Non-JSON text can't be field-masked (same as Sett, which only masks dicts). A field typed `int` in an `output_schema` will fail client-side validation once masked; document "masked fields should be strings". Resources and prompts aren't covered, same as Sett.
6. **Hidden is not unregistered.** Anything that bypasses `FastMCP.call_tool` would bypass the gate. Tests 3, 8 and 9 cover the known paths, and the docs say to add Sett first.
7. **FastMCP's own auth.** Use FastMCP's providers. Sett's writer role becomes `writer_check(get_access_token())`. `require_roles` and `AuthMiddleware` can narrow per tool, but **nothing widens** `<PREFIX>_ENABLE_WRITES`. That invariant goes in the README and in a test.
8. **Resolved by the spike (2026-11-11);** see "Spike results" above:
   - (a) Yes: a middleware-returned `InputRequiredToolResult` completes a round trip with `Client(mode="auto")`.
   - (b) `ctx.session.client_capabilities`. A modern client with no handler shows `None`; if the server asks anyway, the client answers with its own `MCPError: Elicitation not supported`. So check up front, for form support and not just presence (§4).
   - (c) `ctx.session.elicit_form` with a plain dict. An empty dataclass or model through `ctx.elicit` adds a `title`.
   - (d) Yes: tool, argument digest, principal, TTL (600 s) and audience, per [RequestStateSecurity][rss]. A constant marker is enough on our side.
9. **A confirmation can be replayed within its TTL (observed in the spike).** Using the same genuine `request_state` a second time ran the tool body again; neither the SDK nor the middleware refused it. Whoever holds the state (the client) can re-run that exact call for up to 10 minutes. For a non-idempotent write such as `create_contact` that means a duplicate. It's stateless by design, so the middleware alone can't fix it. Decided (open question 7): document it and recommend `RequestStateSecurity(ttl=120)`.

## 9. Sequence

1. **Spike: done 2026-11-11, go** (`spikes/fastmcp-middleware/`). The fallback in §4 is not needed.
2. **Extract `policy.py`** in the template (`confirm_text`, refusal text, `Audit`). No behavior change: the existing template CI must pass unchanged.
3. **Build `sett-fastmcp`**: middleware, `check()`, the tests in §7 and the drift check.
4. **Docs and release**: package README, a README section in Sett ("Using FastMCP?"), the client-support column and the publish workflow.
5. **Later, on demand**: a template `framework` option, and a policy-schema extension if open question 2 lands.

## 10. Open questions (for Kirk)

1. **Proxied tools:** distrust upstream annotations by default (recommended), or trust them and document it?
2. **Tools you can't annotate** (OpenAPI, third-party mounts): add a policy key such as `tools.read: [...]` to classify them? It would change the shared schema for template users too, where it's a no-op. Recommendation: wait for a real request, and use `allow` lists meanwhile.
3. **HTTP without a shared key:** should `check(mcp)` warn when confirmations are on and the server uses the per-process key?
4. **Writer role:** take a callable only (recommended), or also read Sett's `<PREFIX>_WRITER_CLAIM`/`_WRITER_VALUE` env vars for parity with remote mode? And should `StderrAuditSink`/`SupabaseAuditSink` move into `policy.py` so FastMCP users get them? They're stdlib-only, but `remote.py` imports `jwt` at the top.
5. **FastMCP 3.x** (still maintained, on SDK v1): support it? Recommendation: no. It's a different SDK and has no 2026-07-28 confirmation path.
6. **Where this doc lives:** `docs/design/fastmcp-adapter.md` in the repo, or the Sett brief in Second Brain?
7. **Replay within the TTL (new, from the spike):** a genuine confirmation can be used twice inside its TTL (600 s default). Options: recommend a short `RequestStateSecurity(ttl=120)` in the README for servers with non-idempotent writes; require idempotent writes; or accept it and document it. **Decided 2026-11-11:** document it and recommend the short `ttl`. Whether `check(mcp)` can read the server's `RequestStateSecurity` to warn about a long one is untested.

## 11. Verification (when built)
- `uv run --extra dev pytest` in `packages/sett-fastmcp` passes on the matrix, on both protocol eras.
- The template's `test-template.yml` passes unchanged after the `policy.py` extraction, and the drift diff is empty.
- A manual run of the FastMCP sample with `fastmcp dev` / MCP Inspector, then the real-client smoke test (Claude Code, Cursor, Codex, claude.ai).

## Sources

**Sett:**
- [guardrails.py](https://github.com/kclarkedesign/sett-mcp/blob/main/template/src/%7B%7Bpackage_name%7D%7D/guardrails.py)
- [remote.py](https://github.com/kclarkedesign/sett-mcp/blob/main/template/src/%7B%7Bpackage_name%7D%7D/remote.py)
- [server.py.jinja](https://github.com/kclarkedesign/sett-mcp/blob/main/template/src/%7B%7Bpackage_name%7D%7D/server.py.jinja)
- [test_guardrails.py.jinja](https://github.com/kclarkedesign/sett-mcp/blob/main/template/tests/test_guardrails.py.jinja)
- [docs/remote.md.jinja](https://github.com/kclarkedesign/sett-mcp/blob/main/template/docs/remote.md.jinja)

**FastMCP and MCP:**

[pypi]: https://pypi.org/project/fastmcp/
[v4]: https://github.com/PrefectHQ/fastmcp/releases/tag/v4.0.0
[slim]: https://github.com/PrefectHQ/fastmcp/blob/main/fastmcp_slim/pyproject.toml
[up3]: https://gofastmcp.com/getting-started/upgrading/from-fastmcp-3
[mw]: https://gofastmcp.com/servers/middleware
[mwsrc]: https://github.com/PrefectHQ/fastmcp/blob/main/fastmcp_slim/fastmcp/server/middleware/middleware.py
[ops]: https://github.com/PrefectHQ/fastmcp/blob/main/fastmcp_slim/fastmcp/server/mixins/mcp_operations.py
[toolbase]: https://github.com/PrefectHQ/fastmcp/blob/main/fastmcp_slim/fastmcp/tools/base.py
[elic]: https://gofastmcp.com/servers/elicitation
[comp]: https://gofastmcp.com/servers/composition
[vis]: https://gofastmcp.com/servers/visibility
[authz]: https://gofastmcp.com/servers/authorization
[test]: https://gofastmcp.com/servers/testing
[http]: https://gofastmcp.com/deployment/http
[tt]: https://gofastmcp.com/servers/transforms/tool-transformation
[i4929]: https://github.com/PrefectHQ/fastmcp/issues/4929
[eunomia]: https://gofastmcp.com/integrations/eunomia-authorization
[permit]: https://gofastmcp.com/integrations/permit
[approval]: https://gofastmcp.com/apps/providers/approval
[spectools]: https://modelcontextprotocol.io/specification/2026-07-28/server/tools
[schema]: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.ts
[mrtr]: https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
[legacy]: https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/run/legacy-clients.md
[rss]: https://py.sdk.modelcontextprotocol.io/v2/api/mcp/server/request_state/

- FastMCP: [PyPI][pypi] · [v4.0.0 release][v4] · [fastmcp-slim pyproject][slim] · [Upgrading from 3][up3] · [Middleware][mw] · [middleware.py][mwsrc] · [mcp_operations.py][ops] · [tools/base.py][toolbase] · [Elicitation][elic] · [Composition][comp] · [Visibility][vis] · [Authorization][authz] · [Testing][test] · [HTTP deployment][http] · [Tool transformation][tt] · [Issue #4929][i4929] · [MRTR guard tests](https://github.com/PrefectHQ/fastmcp/blob/main/tests/server/test_mrtr_guards.py)
- Prior art: [Eunomia][eunomia] · [Permit.io][permit] · [Approval provider][approval]
- MCP spec 2026-07-28: [Tools][spectools] · [schema.ts][schema] · [MRTR pattern][mrtr] · [Elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation) · [Changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- Python SDK v2: [Migration guide](https://py.sdk.modelcontextprotocol.io/v2/migration/) · [RequestStateSecurity][rss] · [Legacy clients][legacy]
