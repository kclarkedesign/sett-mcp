"""Spike for docs/design/fastmcp-adapter.md section 8 (a)-(d). Throwaway: nothing here ships.

Question: can a FastMCP 4 *middleware* run Sett's confirmation on both protocol eras?

  8a  middleware returns InputRequiredToolResult on the 2026-07-28 protocol; does the round
      trip complete, and does the tool run only after "accept"?
  8b  how does the middleware read client capabilities, and what happens when the client
      has no elicitation handler?
  8c  how to send an EMPTY confirmation form on the old protocol now that
      `ctx.elicit(response_type=None)` is gone (Codex rejects a top-level `title`)?
  8d  does the SDK's request-state sealing already bind principal/TTL, and does our own
      binding stop a forged or replayed confirmation?

Every experiment prints what it actually saw. Nothing is asserted just to look green.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import traceback
from dataclasses import dataclass
from typing import Any

from fastmcp import Client, FastMCP
from fastmcp.client.elicitation import ElicitResult
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware
from fastmcp.tools import InputRequiredToolResult
from mcp.server.request_state import RequestStateSecurity
from mcp_types import (
    ElicitRequest,
    ElicitRequestFormParams,
    InputRequiredResult,
    ToolAnnotations,
)
from pydantic import BaseModel

CONFIRM_KEY = "sett_confirm"
EMPTY_FORM = {"type": "object", "properties": {}}
RESULTS: list[tuple[str, str, str]] = []


def record(tag: str, verdict: str, detail: str) -> None:
    RESULTS.append((tag, verdict, detail))
    print(f"[{verdict}] {tag}: {detail}")


def is_modern(version: Any) -> bool:
    return str(version) >= "2026-07-28"  # ISO dates sort lexicographically


def binding(tool: str, args: dict) -> str:
    return hashlib.sha256(json.dumps([tool, args], sort_keys=True).encode()).hexdigest()[:16]


def safe(fn):
    try:
        return fn()
    except Exception as exc:  # the probe must never break the experiment
        return f"ERR {type(exc).__name__}: {exc}"


@dataclass
class Empty:  # an empty form for the old protocol
    pass


class EmptyModel(BaseModel):
    pass


class SpikeConfirm(Middleware):
    """A 40-line stand-in for SettMiddleware's confirmation step."""

    def __init__(
        self, *, legacy_variant: str = "dataclass", check_capability: bool = True, modern_capability_check: bool = False
    ) -> None:
        self.legacy_variant = legacy_variant
        self.check_capability = check_capability
        self.modern_capability_check = modern_capability_check
        self.rounds: list[dict[str, Any]] = []
        self.notes: dict[str, Any] = {}

    async def on_call_tool(self, context, call_next):
        name = context.message.name
        args = context.message.arguments or {}
        if name != "delete_contact":
            return await call_next(context)
        ctx = context.fastmcp_context
        rc = ctx.request_context
        version = safe(lambda: rc.protocol_version)
        caps = safe(lambda: ctx.session.client_capabilities)
        self.rounds.append(
            {
                "protocol": version,
                "had_input_responses": bool(ctx.input_responses),
                "request_state": ctx.request_state,
                "session_type": type(safe(lambda: ctx.session)).__name__,
                "client_elicitation_cap": safe(lambda: caps.elicitation) if not isinstance(caps, str) else caps,
            }
        )
        if "annotations" not in self.notes:
            tool = await ctx.fastmcp.get_tool(name)
            self.notes["annotations"] = None if tool is None else tool.annotations
        prompt = f"Permanently delete contact {args.get('contact_id')}?"

        if is_modern(version):
            answer = (ctx.input_responses or {}).get(CONFIRM_KEY)
            expected = binding(name, args)
            if answer is None and self.modern_capability_check:
                if isinstance(caps, str) or caps is None or caps.elicitation is None:
                    raise ToolError("delete_contact was not run: this connection can't carry a confirmation prompt.")
            if answer is None:
                return InputRequiredToolResult(
                    InputRequiredResult(
                        result_type="input_required",
                        input_requests={
                            CONFIRM_KEY: ElicitRequest(
                                method="elicitation/create",
                                params=ElicitRequestFormParams(message=prompt, requested_schema=EMPTY_FORM),
                            )
                        },
                        request_state=expected,
                    )
                )
            if ctx.request_state != expected:
                raise ToolError("delete_contact was not run: the confirmation doesn't match this request.")
            if answer.action == "accept":
                return await call_next(context)
            raise ToolError(
                "delete_contact was not run: the user declined."
                if answer.action == "decline"
                else "delete_contact was not run: the confirmation was cancelled."
            )

        # old protocol: server-initiated elicitation
        if self.check_capability:
            has = not isinstance(caps, str) and caps is not None and caps.elicitation is not None
            if not has:
                raise ToolError("delete_contact was not run: this connection can't carry a confirmation prompt.")
        if self.legacy_variant == "dataclass":
            result = await ctx.elicit(prompt, response_type=Empty)
        elif self.legacy_variant == "pydantic":
            result = await ctx.elicit(prompt, response_type=EmptyModel)
        elif self.legacy_variant == "session_form":
            result = await ctx.session.elicit_form(prompt, EMPTY_FORM)
        else:
            raise AssertionError(self.legacy_variant)
        if result.action == "accept":
            return await call_next(context)
        raise ToolError(
            "delete_contact was not run: the user declined."
            if result.action == "decline"
            else "delete_contact was not run: the confirmation was cancelled."
        )


def build(mw: SpikeConfirm, *, key: str | None = None) -> tuple[FastMCP, dict[str, dict]]:
    store = {"c1": {"id": "c1", "name": "Ada"}, "c2": {"id": "c2", "name": "Bo"}}
    kw: dict[str, Any] = {}
    if key:
        kw["request_state_security"] = RequestStateSecurity(keys=[key])
    mcp = FastMCP("Spike", middleware=[mw], **kw)

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    def search_contacts(query: str) -> list[dict]:
        """Search contacts."""
        return [c for c in store.values() if query.lower() in c["name"].lower()]

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True))
    def delete_contact(contact_id: str) -> dict:
        """Delete a contact."""
        return store.pop(contact_id)

    return mcp, store


def handler_factory(action: str, seen: list):
    async def handler(message, response_type, params, context):
        schema = getattr(params, "requested_schema", None)
        seen.append({"message": message, "schema": schema, "response_type": response_type})
        return ElicitResult(action=action, content={} if action == "accept" else None)

    return handler


async def attempt(client_kwargs: dict, mw: SpikeConfirm, args: dict | None = None):
    """Call delete_contact once. Returns (store, outcome string, handler calls)."""
    mcp, store = build(mw)
    seen: list = []
    kwargs = dict(client_kwargs)
    action = kwargs.pop("action", None)
    if action:
        kwargs["elicitation_handler"] = handler_factory(action, seen)
    try:
        async with Client(mcp, **kwargs) as client:
            res = await client.call_tool("delete_contact", args or {"contact_id": "c1"})
            outcome = f"returned ok ({res.data!r})"
    except Exception as exc:
        outcome = f"{type(exc).__name__}: {exc}"
    return store, outcome, seen


async def e1_to_e4_modern() -> None:
    mw = SpikeConfirm()
    store, outcome, seen = await attempt({"mode": "auto", "action": "accept"}, mw)
    rounds = len(mw.rounds)
    ok = "c1" not in store and len(seen) == 1 and rounds == 2
    record("8a accept (auto)", "PASS" if ok else "FAIL",
           f"outcome={outcome}; c1 deleted={'c1' not in store}; handler calls={len(seen)}; middleware rounds={rounds}")
    if seen:
        record("8a form on the wire", "INFO", f"message={seen[0]['message']!r}; schema={seen[0]['schema']}")
    record("8a annotations visible to middleware", "INFO", f"{mw.notes.get('annotations')}")
    record("8b modern: what middleware sees per round", "INFO", json.dumps(mw.rounds, default=str)[:600])

    for action, expect in (("decline", "declined"), ("cancel", "cancelled")):
        mw = SpikeConfirm()
        store, outcome, seen = await attempt({"mode": "auto", "action": action}, mw)
        ok = "c1" in store and expect in outcome
        record(f"8a {action} (auto)", "PASS" if ok else "FAIL", f"outcome={outcome}; c1 kept={'c1' in store}")

    mw = SpikeConfirm()
    store, outcome, _ = await attempt({"mode": "auto"}, mw)
    record("8b modern, client has NO handler", "PASS" if "c1" in store else "FAIL",
           f"outcome={outcome}; c1 kept={'c1' in store}; middleware rounds={len(mw.rounds)}")
    record("8b modern, no handler: capabilities server saw", "INFO", json.dumps(mw.rounds, default=str)[:600])

    mw = SpikeConfirm(modern_capability_check=True)
    store, outcome, _ = await attempt({"mode": "auto"}, mw)
    record("8b modern, no handler, capability checked UP FRONT",
           "PASS" if "c1" in store and "can't carry" in outcome else "FAIL",
           f"outcome={outcome}; c1 kept={'c1' in store}; middleware rounds={len(mw.rounds)}")


async def e5_to_e7_legacy() -> None:
    mw = SpikeConfirm()
    store, outcome, seen = await attempt({"mode": "legacy", "action": "accept"}, mw)
    record("8a legacy accept", "PASS" if "c1" not in store and len(seen) == 1 else "FAIL",
           f"outcome={outcome}; c1 deleted={'c1' not in store}; handler calls={len(seen)}; protocol={mw.rounds[0]['protocol'] if mw.rounds else None}")
    record("8b legacy: capabilities server saw", "INFO", json.dumps(mw.rounds, default=str)[:600])

    mw = SpikeConfirm()
    store, outcome, _ = await attempt({"mode": "legacy"}, mw)
    record("8b legacy, no handler, capability check", "PASS" if "c1" in store and "can't carry" in outcome else "FAIL",
           f"outcome={outcome}; c1 kept={'c1' in store}")

    mw = SpikeConfirm(check_capability=False)
    store, outcome, _ = await attempt({"mode": "legacy"}, mw)
    record("8b legacy, no handler, NO capability check (what ctx.elicit raises)", "INFO",
           f"outcome={outcome}; c1 kept={'c1' in store}")

    for variant in ("dataclass", "pydantic", "session_form"):
        mw = SpikeConfirm(legacy_variant=variant)
        store, outcome, seen = await attempt({"mode": "legacy", "action": "accept"}, mw)
        if seen:
            raw = seen[0]["schema"]
            dumped = raw if isinstance(raw, dict) else getattr(raw, "model_dump", lambda **k: raw)(by_alias=True, exclude_none=True)
            keys = set(dumped) if isinstance(dumped, dict) else None
            spec_ok = keys is not None and keys <= {"$schema", "type", "properties", "required"}
            record(f"8c empty form via {variant}", "PASS" if spec_ok else "FAIL",
                   f"schema={dumped}; top-level keys ok={spec_ok}; c1 deleted={'c1' not in store}; outcome={outcome}")
        else:
            record(f"8c empty form via {variant}", "FAIL", f"client never saw a prompt; outcome={outcome}")


async def e8_binding() -> None:
    # Source: what does the SDK bind into the sealed state?
    import inspect

    import mcp.server.request_state as rs

    src = inspect.getsource(rs)
    hits = [ln.strip() for ln in src.splitlines() if any(k in ln.lower() for k in ("bind_principal", "principal", "audience", "ttl", "expires"))]
    record("8d SDK sealing source mentions", "INFO", " | ".join(hits[:14]))

    # Raw rounds: forged accept with no state, and a replay of real state against other args.
    mw = SpikeConfirm()
    mcp, store = build(mw, key="k" * 32)
    seen: list = []
    async with Client(mcp, mode="auto", elicitation_handler=handler_factory("accept", seen)) as client:
        session = client.session
        record("8d raw rounds: client.session type", "INFO", f"{type(session).__module__}.{type(session).__name__}")
        call = getattr(session, "call_tool", None)
        if call is None:
            record("8d forged first round", "INFO", "client.session has no call_tool; skipped")
            return
        forged = {CONFIRM_KEY: ElicitResult(action="accept", content={})}
        for label, kwargs in (
            ("forged accept, no request_state", {"input_responses": forged, "request_state": None}),
            ("forged accept, made-up request_state", {"input_responses": forged, "request_state": "v1.not-a-real-token"}),
        ):
            try:
                res = await call("delete_contact", {"contact_id": "c1"}, **kwargs)
                outcome = f"returned {type(res).__name__}: {str(res)[:160]}"
            except Exception as exc:
                outcome = f"{type(exc).__name__}: {str(exc)[:160]}"
            record(f"8d {label}", "PASS" if "c1" in store else "FAIL", f"{outcome}; c1 kept={'c1' in store}")

        # A GENUINE sealed state from round 1 (ask for c1), replayed against other arguments.
        try:
            first = await call("delete_contact", {"contact_id": "c1"}, allow_input_required=True)
        except Exception as exc:
            record("8d genuine replay: round 1", "INFO", f"could not get round 1 raw: {type(exc).__name__}: {exc}")
            return
        state = getattr(first, "request_state", None)
        record("8d genuine replay: round 1 type", "INFO", f"{type(first).__name__}; sealed request_state present={bool(state)}; "
               f"prefix={str(state)[:6]!r}; plaintext leaked={'f97a' in str(state) or binding('delete_contact', {'contact_id': 'c1'}) in str(state)}")
        if not state:
            return
        for label, args in (("same args (c1)", {"contact_id": "c1"}), ("DIFFERENT args (c2)", {"contact_id": "c2"})):
            try:
                res = await call("delete_contact", args, input_responses=forged, request_state=state, allow_input_required=True)
                outcome = f"returned {type(res).__name__}: {str(res)[:150]}"
            except Exception as exc:
                outcome = f"{type(exc).__name__}: {str(exc)[:150]}"
            gone = [k for k in ("c1", "c2") if k not in store]
            record(f"8d genuine state replayed with {label}", "INFO", f"{outcome}; deleted={gone}")
        record("8d replay summary", "PASS" if "c2" in store else "FAIL", f"c2 kept={'c2' in store} (must be True: state was issued for c1)")

        # Single-use? The same genuine state, a SECOND time. c1 is already gone, so if the tool
        # body runs again it fails with KeyError('c1'); if the SDK refuses the token we see that instead.
        try:
            res = await call("delete_contact", {"contact_id": "c1"}, input_responses=forged, request_state=state, allow_input_required=True)
            outcome = f"returned {type(res).__name__}: is_error={getattr(res, 'is_error', None)} {str(res)[:170]}"
        except Exception as exc:
            outcome = f"{type(exc).__name__}: {str(exc)[:170]}"
        record("8d same genuine state, SECOND use", "INFO", outcome)


async def main() -> None:
    for fn in (e1_to_e4_modern, e5_to_e7_legacy, e8_binding):
        try:
            await fn()
        except Exception:
            record(fn.__name__, "ERROR", traceback.format_exc(limit=4).replace("\n", " | ")[:900])
    print("\n==== SUMMARY ====")
    for tag, verdict, _ in RESULTS:
        print(f"{verdict:6} {tag}")


if __name__ == "__main__":
    asyncio.run(main())
