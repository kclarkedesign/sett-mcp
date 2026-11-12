"""Does FastMCP's ResponseCachingMiddleware interact badly with Sett-style writes?
(Codex review of PR #18, P2.) Throwaway, like the other scripts here.

Each case calls a confirmed write (`delete_contact`, destructive) and an unconfirmed write
(`create_contact`, which stands for `confirm: off` or a non-destructive write) TWICE with
identical arguments, accepting every prompt, and counts how often the handler really ran
and how often the user was really asked. A safe stack gives runs 2/2 and prompts 2/2.

  sett-outer  = middleware=[sett, cache]   (Sett added first, the doc's rule)
  cache-outer = middleware=[cache, sett]
  exclude     = the cache is told not to cache these two tools (`call_tool_settings`)
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fastmcp import Client, FastMCP  # noqa: E402
from fastmcp.server.middleware.caching import ResponseCachingMiddleware  # noqa: E402
from mcp_types import ToolAnnotations  # noqa: E402
from spike import SpikeConfirm, handler_factory  # noqa: E402

WRITES = ["delete_contact", "create_contact"]


def make(order: str, exclude: bool) -> tuple[FastMCP, dict[str, int]]:
    runs = {"delete": 0, "create": 0}
    sett = SpikeConfirm(legacy_variant="session_form", modern_capability_check=True)
    cache = ResponseCachingMiddleware(call_tool_settings={"excluded_tools": WRITES} if exclude else None)
    mcp = FastMCP("Spike", middleware=[sett, cache] if order == "sett-outer" else [cache, sett])

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True))
    def delete_contact(contact_id: str) -> dict:
        """Delete a contact (confirmed)."""
        runs["delete"] += 1
        return {"id": contact_id}

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False))
    def create_contact(name: str) -> dict:
        """Create a contact (not confirmed)."""
        runs["create"] += 1
        return {"name": name}

    return mcp, runs


async def case(mode: str, order: str, exclude: bool) -> None:
    mcp, runs = make(order, exclude)
    seen: list = []
    outcomes = []
    async with Client(mcp, mode=mode, elicitation_handler=handler_factory("accept", seen)) as client:
        for _ in range(2):
            for tool, args in (("delete_contact", {"contact_id": "c1"}), ("create_contact", {"name": "Bo"})):
                try:
                    await client.call_tool(tool, args)
                    outcomes.append("ok")
                except Exception as exc:
                    outcomes.append(f"{type(exc).__name__}")
    del_ok, cre_ok = runs["delete"] == 2, runs["create"] == 2
    asked_ok = len(seen) == 2
    problems = []
    if not del_ok:
        problems.append(f"confirmed write ran {runs['delete']}/2 (handler skipped, caller saw success)")
    if not asked_ok:
        problems.append(f"user asked {len(seen)}/2 times" + (" (confirmation bypassed)" if len(seen) < 2 else ""))
    if not cre_ok:
        problems.append(f"unconfirmed write ran {runs['create']}/2 (handler skipped, caller saw success)")
    verdict = "SAFE " if not problems else "UNSAFE"
    print(f"[{verdict}] {mode:6} {order:11} exclude={exclude!s:5}: runs delete={runs['delete']}/2 create={runs['create']}/2, "
          f"prompts={len(seen)}/2; client saw {outcomes.count('ok')}/4 successes" + ("; " + "; ".join(problems) if problems else ""))


def check_visibility() -> None:
    """Could a future `check(mcp)` see the cache and its call-tool settings?"""
    mcp, _ = make("sett-outer", exclude=True)
    stack = getattr(mcp, "middleware", None)
    cache = next((m for m in (stack or []) if isinstance(m, ResponseCachingMiddleware)), None)
    names = [type(m).__name__ for m in stack] if stack is not None else "not exposed"
    settings = getattr(cache, "_call_tool_settings", "not readable") if cache is not None else "no cache in stack"
    print(f"[INFO  ] check() visibility: mcp.middleware={names}; cache._call_tool_settings (private attribute)={settings}")


async def main() -> None:
    check_visibility()
    for mode in ("auto", "legacy"):
        for order in ("sett-outer", "cache-outer"):
            for exclude in (False, True):
                try:
                    await case(mode, order, exclude)
                except Exception as exc:
                    print(f"[ERROR ] {mode} {order} exclude={exclude}: {type(exc).__name__}: {str(exc)[:200]}")


if __name__ == "__main__":
    asyncio.run(main())
