"""Single-use confirmations (Codex review of PR #27, finding P1). Throwaway, like spike.py.

The SDK seals (tool, args digest, principal) into `request_state` but does not make it
single-use (spike.py 8d). Here the middleware puts a random nonce in the state and keeps the
nonces it has seen in memory, so a second presentation is refused. Checked:

  R1  the same accepted state presented twice: the tool body runs once
  R2  decline, then accept with the same state: the accept is refused (first answer wins)
  R3  two concurrent presentations of one state: exactly one runs
  R4  a fresh ask gives a fresh nonce that works once
  R5  limit: the window must be at least the SDK's ttl, or a late replay gets through
  R6  limit: with two instances sharing a state key, round 2 may go to either instance (good),
      but a replay sent to the OTHER instance is not caught (per-instance memory)
"""

from __future__ import annotations

import asyncio
import secrets
import time
from typing import Any

from fastmcp import Client, FastMCP
from fastmcp.client.elicitation import ElicitResult
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware
from fastmcp.tools import InputRequiredToolResult
from mcp.server.request_state import RequestStateSecurity
from mcp_types import ElicitRequest, ElicitRequestFormParams, InputRequiredResult, ToolAnnotations

KEY = "k" * 32
CONFIRM_KEY = "sett_confirm"
PREFIX = "sett-confirm-v1"
RESULTS: list[tuple[str, str]] = []


def record(tag: str, verdict: str, detail: str) -> None:
    RESULTS.append((tag, verdict))
    print(f"[{verdict}] {tag}: {detail}")


class SingleUse(Middleware):
    """Per-instance single-use confirmation. Modern protocol only (the old one has no replayable state)."""

    def __init__(self, window: float = 600.0, clock=time.monotonic) -> None:
        self.window = window
        self.clock = clock
        self.used: dict[str, float] = {}  # nonce -> expiry

    def _purge(self) -> None:
        now = self.clock()
        for nonce in [n for n, expiry in self.used.items() if expiry <= now]:
            del self.used[nonce]

    async def on_call_tool(self, context, call_next):
        if context.message.name != "delete_contact":
            return await call_next(context)
        ctx = context.fastmcp_context
        args = context.message.arguments or {}
        answer = (ctx.input_responses or {}).get(CONFIRM_KEY)
        if answer is None:
            return InputRequiredToolResult(
                InputRequiredResult(
                    result_type="input_required",
                    input_requests={
                        CONFIRM_KEY: ElicitRequest(
                            method="elicitation/create",
                            params=ElicitRequestFormParams(
                                message=f"Permanently delete contact {args.get('contact_id')}?",
                                requested_schema={"type": "object", "properties": {}},
                            ),
                        )
                    },
                    request_state=f"{PREFIX}:{secrets.token_urlsafe(16)}",
                )
            )
        prefix, _, nonce = (ctx.request_state or "").partition(":")
        if prefix != PREFIX or not nonce:
            raise ToolError("delete_contact was not run: the confirmation doesn't match this request.")
        self._purge()
        if nonce in self.used:
            raise ToolError("delete_contact was not run: this confirmation was already used. Ask again.")
        # Check and insert with no `await` between them, so this is atomic on one event loop.
        # Consumed on first presentation whatever the answer: one confirmation, one answer.
        self.used[nonce] = self.clock() + self.window
        if answer.action != "accept":
            raise ToolError("delete_contact was not run: not confirmed.")
        return await call_next(context)


def build(mw: SingleUse, runs: list[str]) -> FastMCP:
    mcp = FastMCP("Spike", middleware=[mw], request_state_security=RequestStateSecurity(keys=[KEY]))

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True))
    def delete_contact(contact_id: str) -> dict:
        """Delete a contact."""
        runs.append(contact_id)  # counts executions, so a repeat can't hide behind a KeyError
        return {"id": contact_id}

    return mcp


async def ask(session: Any, args: dict) -> str:
    first = await session.call_tool("delete_contact", args, allow_input_required=True)
    return first.request_state


async def present(session: Any, args: dict, state: str, action: str = "accept") -> str:
    answer = ElicitResult(action=action, content={} if action == "accept" else None)
    try:
        res = await session.call_tool(
            "delete_contact", args, input_responses={CONFIRM_KEY: answer}, request_state=state, allow_input_required=True
        )
    except Exception as exc:
        return f"{type(exc).__name__}: {str(exc)[:90]}"
    text = "".join(getattr(c, "text", "") for c in getattr(res, "content", []) or [])
    return f"{'error' if getattr(res, 'is_error', False) else 'ok'}: {text[:90]}"


async def r1_to_r4() -> None:
    runs: list[str] = []
    mw = SingleUse()
    async with Client(build(mw, runs), mode="auto") as client:
        s = client.session
        args = {"contact_id": "c1"}
        state = await ask(s, args)
        a = await present(s, args, state)
        b = await present(s, args, state)
        record("R1 same state twice", "PASS" if runs == ["c1"] else "FAIL", f"runs={runs}; 1st={a!r}; 2nd={b!r}")

        state = await ask(s, {"contact_id": "c2"})
        d = await present(s, {"contact_id": "c2"}, state, action="decline")
        e = await present(s, {"contact_id": "c2"}, state, action="accept")
        record("R2 decline then accept, same state", "PASS" if "c2" not in runs else "FAIL", f"runs={runs}; decline={d!r}; accept={e!r}")

        state = await ask(s, {"contact_id": "c3"})
        before = len(runs)
        results = await asyncio.gather(*(present(s, {"contact_id": "c3"}, state) for _ in range(2)))
        record("R3 two concurrent presentations", "PASS" if len(runs) - before == 1 else "FAIL", f"ran {len(runs) - before} time(s); {results!r}")

        again = await ask(s, args)
        ok = again != state and (await present(s, args, again)).startswith("ok") and runs.count("c1") == 2
        record("R4 a fresh ask gives a fresh, working nonce", "PASS" if ok else "FAIL", f"runs={runs}")


async def r5_window_shorter_than_ttl() -> None:
    runs: list[str] = []
    offset = [0.0]
    mw = SingleUse(window=60.0, clock=lambda: time.monotonic() + offset[0])
    async with Client(build(mw, runs), mode="auto") as client:
        s = client.session
        args = {"contact_id": "c1"}
        state = await ask(s, args)
        await present(s, args, state)
        offset[0] += 61  # past our 60 s window, still inside the SDK's 600 s ttl
        late = await present(s, args, state)
        record("R5 replay after our window, inside the SDK ttl", "INFO",
               f"runs={runs}; late replay={late!r} (a second run means the window must be >= the SDK ttl)")


async def r6_two_instances() -> None:
    runs_a: list[str] = []
    runs_b: list[str] = []
    a, b = build(SingleUse(), runs_a), build(SingleUse(), runs_b)
    async with Client(a, mode="auto") as ca, Client(b, mode="auto") as cb:
        args = {"contact_id": "c1"}
        state = await ask(ca.session, args)  # round 1 on instance A
        first = await present(cb.session, args, state)  # round 2 on instance B (shared key)
        replay_b = await present(cb.session, args, state)
        replay_a = await present(ca.session, args, state)
        record("R6a round 1 on A, round 2 on B (shared key)", "PASS" if runs_b == ["c1"] else "FAIL", f"B runs={runs_b}; {first!r}")
        record("R6b replay to the same instance (B)", "PASS" if runs_b == ["c1"] else "FAIL", f"{replay_b!r}")
        record("R6c replay to the OTHER instance (A)", "INFO",
               f"A runs={runs_a}; {replay_a!r} (a run here is the per-instance limit: A never saw this nonce)")


async def main() -> None:
    for fn in (r1_to_r4, r5_window_shorter_than_ttl, r6_two_instances):
        try:
            await fn()
        except Exception as exc:
            import traceback

            record(fn.__name__, "ERROR", traceback.format_exc(limit=3).replace("\n", " | ")[:600])


if __name__ == "__main__":
    asyncio.run(main())
