# FastMCP middleware spike: results (2026-11-11)

Answers §8 (a)-(d) of `docs/design/fastmcp-adapter.md` (on branch `fastmcp-adapter-plan`).
**Verdict: go. Option A (middleware as the only enforcement layer) holds; the §4 fallback is not needed.**

Run: `uv run --no-project --system-certs --python-preference only-system --python 3.14 --with "fastmcp>=4.1,<5" python spikes/fastmcp-middleware/spike.py`
Tested on: fastmcp 4.1.8, mcp 2.3.0, mcp-types 2.3.0, **Python 3.14.10 only**. Raw output: `last-run.txt` (11 PASS, 12 INFO, 2 FAIL; both FAILs are finding 3).

## Findings

1. **8a: middleware can run the 2026-07-28 confirmation.** Returning `InputRequiredToolResult(InputRequiredResult(...))` from `on_call_tool` completes the round trip with `Client(mode="auto")`: 2 middleware rounds, handler called once, the tool ran only after `accept`. `decline` and `cancel` ran nothing and reported distinct messages. The legacy path (`mode="legacy"`) also works from the same middleware. The wire form was `{'properties': {}, 'type': 'object'}` (no `title`).
2. **8b: read capabilities from `ctx.session.client_capabilities`, on both eras.** On the modern protocol they arrive per request: a client with a handler shows `form` and `url` elicitation; a client without one shows `None`. **Check this up front on both eras, and test for form support, not just presence** (see the correction below). Without the check, a modern client with no handler still fails safe (the tool did not run) but surfaces the client's raw `MCPError: Elicitation not supported`, with no Sett message and no `blocked` audit entry. With the check: `ToolError: ... can't carry a confirmation prompt`, one round. On the legacy path, calling `ctx.elicit` without the check raises `MCPError: Elicitation not supported` (answers the "exact exception class" question).
3. **8c: do not use `ctx.elicit()` for the empty form.** An empty dataclass and an empty pydantic model both send a top-level `title` (`'Empty'`, `'EmptyModel'`), which is what Codex rejects. **Use `await ctx.session.elicit_form(message, {"type": "object", "properties": {}})`**: the schema arrives clean and the result has `.action`. Add a test equivalent to Sett's `test_confirmation_form_uses_only_fields_the_spec_allows`.
4. **8d: the SDK already seals request binding; our own hash is redundant.** `RequestStateSecurity` seals `(target, args_digest, principal)` plus a TTL (600 s default) and an audience. Observed: a genuine state replayed with different arguments is refused by the SDK (`requestState rejected ... request binding`, `MCPError: Invalid or expired requestState`), and a made-up state is refused too. The sealed token is opaque (`v1.` prefix, no plaintext). **But the SDK does not stop a forged accept with no state at all**: that reached the middleware. Our check (`request_state` must be present) is what refused it. So: replace the §4 sha256 `binding` with a constant marker, and keep requiring it.
5. Tool annotations are visible to middleware through `await ctx.fastmcp.get_tool(name)` (`read_only_hint`, `destructive_hint`, `idempotent_hint`, `open_world_hint`; unset ones are `None`, so the spec defaults must be applied in `kind()`).

## Changes to make in the design doc

- §4 `on_call_tool` step 3: capability check first, on both eras, then branch. Legacy path uses `ctx.session.elicit_form` with a plain dict, not `ctx.elicit`.
- §4 `binding`: replace with a constant marker; say that the SDK binds tool, argument digest, principal and TTL.
- §7 test 5: the spike **refuses** a forged first round; the plan says "re-asks". Refusing is simpler and safer, so change the wording. Test 6 becomes a regression test for the SDK's own rejection.
- §8 risks, new, **observed**: a sealed state is **not single-use**. Using the same genuine state a second time ran the tool body again (it failed with `KeyError: 'c1'` only because the contact was already deleted); neither the SDK nor the middleware refused it. Within the TTL (600 s default), whoever holds the state can re-run that exact call. For a non-idempotent write such as `create_contact`, that means a duplicate. Stateless by design, so no fix inside the middleware alone: shorten `ttl`, or make the write idempotent. Worth an open question in the design doc.
- §8 item 8 is resolved: (a) yes, (b) `ctx.session.client_capabilities`, (c) `ctx.session.elicit_form`, (d) yes, partly.

## Not covered by this spike

- Python 3.10 and 3.13 (the planned CI matrix) were not run. fastmcp 4.1.8, fastmcp-slim and mcp 2.3.0 all declare `Requires-Python: >=3.10`, so the matrix is allowed, but unproven.
- Real clients (Claude Code, Cursor, Codex, claude.ai, Claude Desktop).
- Two instances sharing a `RequestStateSecurity` key (planned test 7). The spike only passed a key; it never split rounds across two servers.
- Mounted, proxied and OpenAPI tools; `stateless_http`; masking, audit, writer check; interplay with `AuthMiddleware` and a real token (principal binding was only observed unauthenticated, where the SDK says the state is not principal-bound).

## Correction after Codex review of PR #27

`spike.py` checks `caps.elicitation is None`, which only proves a client **has** elicitation. A client can declare only `url` (it can't show our form), and the spec says an empty `elicitation: {}` means form only. The rule to use is `e is not None and (e.form is not None or e.url is None)`, and the SDK's own `check_client_capability` is no help: it checks presence only. `capabilities.py` runs the rule against the SDK's real capability models (6 cases, all pass) and shows the SDK check returning True for a URL-only client. Not exercised: a URL-only client end to end. `spike.py` is left as it was run, since its two clients (with and without a handler) behave the same under either check.

## Environment note

`uv` could not download a managed Python here (`invalid peer certificate: UnknownIssuer` from github.com). Using the installed Python and `--system-certs` worked. No certificate checks were bypassed.
