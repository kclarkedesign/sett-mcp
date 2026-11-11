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
- §4 `binding`: replace with a `sett-confirm-v1:<nonce>` request state; say that the SDK binds tool, argument digest, principal and TTL, and that the nonce makes the confirmation single-use (see "Replay mitigation" below).
- §7 test 5: the spike **refuses** a forged first round; the plan says "re-asks". Refusing is simpler and safer, so change the wording. Test 6 becomes a regression test for the SDK's own rejection.
- §8 risks, new, **observed**: a sealed state is **not single-use**. Using the same genuine state a second time ran the tool body again (it failed with `KeyError: 'c1'` only because the contact was already deleted); neither the SDK nor the middleware refused it. Within the TTL (600 s default), whoever holds the state can re-run that exact call. For a non-idempotent write such as `create_contact`, that means a duplicate. Stateless by design, so the middleware has to remember what it has seen: see "Replay mitigation" below.
- §8 item 8 is resolved: (a) yes, (b) `ctx.session.client_capabilities`, (c) `ctx.session.elicit_form`, (d) yes, partly.

## Not covered by this spike

- Python 3.10 and 3.13 (the planned CI matrix) were not run. fastmcp 4.1.8, fastmcp-slim and mcp 2.3.0 all declare `Requires-Python: >=3.10`, so the matrix is allowed, but unproven.
- Real clients (Claude Code, Cursor, Codex, claude.ai, Claude Desktop).
- Two instances sharing a `RequestStateSecurity` key (planned test 7): the positive path (round 1 on A, round 2 on B) is covered by `replay.py` R6a; refusal with different keys is not.
- Mounted, proxied and OpenAPI tools; `stateless_http`; masking, audit, writer check; interplay with `AuthMiddleware` and a real token (principal binding was only observed unauthenticated, where the SDK says the state is not principal-bound).

## Correction after Codex review of PR #27

`spike.py` checks `caps.elicitation is None`, which only proves a client **has** elicitation. A client can declare only `url` (it can't show our form), and the spec says an empty `elicitation: {}` means form only. The rule to use is `e is not None and (e.form is not None or e.url is None)`, and the SDK's own `check_client_capability` is no help: it checks presence only. `capabilities.py` runs the rule against the SDK's real capability models (6 cases, all pass) and shows the SDK check returning True for a URL-only client. Not exercised: a URL-only client end to end. `spike.py` is left as it was run, since its two clients (with and without a handler) behave the same under either check.

## Replay mitigation (after Codex review of PR #27)

Codex pointed out that documenting the replay and shortening the `ttl` only narrows the window. `replay.py` tests the alternative the design now uses: a random nonce in the request state (`sett-confirm-v1:<nonce>`), consumed in memory on first presentation. Output: `replay-run.txt` (6 PASS, 2 INFO, 0 FAIL).

- **Works on one instance.** R1: a second use of the same state is refused and the tool ran once. R2: an accept after a decline on the same state is refused (first answer wins). R3: two concurrent presentations of one state, exactly one runs (check and insert have no `await` between them). R4: a fresh ask gives a fresh nonce that works once.
- **Limits, shown not assumed.** R5: if the middleware's window is shorter than the SDK's `ttl`, a late replay runs, so the window must be at least the `ttl`. R6c: a replay sent to a *different* instance runs, because that instance never saw the nonce. A shared store is the answer for multi-replica servers; it is an extension point, not built.
- **Side result.** R6a: round 1 on instance A and round 2 on instance B, with the same state key, completes and the tool runs once. Planned test 7's positive path works.
- **Not covered:** behavior across a restart, and what real clients do on a retry (the Cursor retry in Sett's client table is not reproduced here).

## Environment note

`uv` could not download a managed Python here (`invalid peer certificate: UnknownIssuer` from github.com). Using the installed Python and `--system-certs` worked. No certificate checks were bypassed.
