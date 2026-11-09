"""Safety layer for MCP tools.

Every tool is registered through `Guardrails.read` or `Guardrails.write`, which apply
four rules taken from the policy:

1. Write gate: write tools are not registered unless writes are enabled, so the model
   can't see them, let alone call them.
2. Allow/deny lists: a tool the policy rules out is never registered.
3. Confirmation: destructive calls pause and ask the user first. Clients that can't
   show a prompt are refused rather than allowed through.
4. Masking: fields such as `email` are replaced before a result reaches the model,
   and in the audit log. A write that passes the "[masked]" placeholder back is
   refused, so a model can't overwrite real data with it.

Each call is also appended to a JSON Lines audit log when one is configured, and sent to
any extra audit sinks (remote mode adds stderr and a Supabase table).

In remote mode a fifth rule applies: write tools also require the signed-in user's
writer role. It narrows what `<PREFIX>_ENABLE_WRITES` allows; it can never widen it.
"""

from __future__ import annotations

import functools
import inspect
import json
import logging
import os
import string
import time
import typing
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Annotated, Any, Literal

import anyio.to_thread
import yaml
from mcp.server.mcpserver import (
    AcceptedElicitation,
    CancelledElicitation,
    Context,
    Elicit,
    ElicitationResult,
    MCPServer,
    Resolve,
)
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, ValidationError

log = logging.getLogger(__name__)

MASK = "[masked]"
ConfirmMode = Literal["destructive", "all_writes", "off"]
_TRUTHY = {"1", "true", "yes", "on"}


class PolicyError(ValueError):
    """The policy file is missing, malformed or contains unknown keys."""


class _ToolLists(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allow: list[str] | None = None
    deny: list[str] = []


class _Audit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str | None = None


class _PolicyFile(BaseModel):
    # extra="forbid" turns a typo like `mask_feilds` into a startup error instead of a
    # silently unmasked field. It also means the file cannot carry a `writes` key:
    # enabling writes is deliberately an environment decision, made by whoever runs
    # the server, not a line someone can commit to the repo.
    model_config = ConfigDict(extra="forbid")
    confirm: ConfirmMode = "destructive"
    tools: _ToolLists = _ToolLists()
    mask_fields: list[str] = []
    audit: _Audit = _Audit()


@dataclass(frozen=True)
class Policy:
    writes_enabled: bool = False
    confirm: ConfirmMode = "destructive"
    allow: frozenset[str] | None = None
    deny: frozenset[str] = frozenset()
    mask_fields: frozenset[str] = frozenset()
    audit_path: Path | None = None

    @classmethod
    def load(
        cls,
        env_prefix: str,
        *,
        package: str | None = None,
        env: Mapping[str, str] = os.environ,
    ) -> Policy:
        """Build the policy from `<PREFIX>_POLICY` (or the packaged default) and the environment.

        `<PREFIX>_ENABLE_WRITES=true` is the only way to turn writes on.
        """
        custom = env.get(f"{env_prefix}_POLICY")
        if custom:
            text = _read_policy_text(Path(custom).expanduser())
        elif package:
            text = resources.files(package).joinpath("default_policy.yaml").read_text()
        else:
            text = ""
        return cls.from_yaml(
            text,
            writes_enabled=env.get(f"{env_prefix}_ENABLE_WRITES", "").strip().lower() in _TRUTHY,
        )

    @classmethod
    def from_yaml(cls, text: str, *, writes_enabled: bool = False) -> Policy:
        try:
            raw = yaml.safe_load(text) or {}
            parsed = _PolicyFile.model_validate(raw)
        except (yaml.YAMLError, ValidationError) as exc:
            raise PolicyError(f"Invalid policy: {exc}") from exc
        return cls(
            writes_enabled=writes_enabled,
            confirm=parsed.confirm,
            allow=frozenset(parsed.tools.allow) if parsed.tools.allow else None,
            deny=frozenset(parsed.tools.deny),
            mask_fields=frozenset(f.lower() for f in parsed.mask_fields),
            audit_path=Path(parsed.audit.path).expanduser() if parsed.audit.path else None,
        )

    def permits(self, tool: str) -> bool:
        return tool not in self.deny and (self.allow is None or tool in self.allow)


def _read_policy_text(path: Path) -> str:
    try:
        return path.read_text()
    except OSError as exc:
        raise PolicyError(f"Cannot read policy file {path}: {exc}") from exc


def mask(value: Any, fields: frozenset[str]) -> Any:
    """Replace the values of `fields` (case-insensitive) anywhere in a nested result.

    Empty values (None) are left alone, so "not set" doesn't read as "hidden".
    """
    if not fields:
        return value
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {
            k: MASK if str(k).lower() in fields and v is not None else mask(v, fields) for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [mask(v, fields) for v in value]
    return value


def _form_schema(schema: dict[str, Any]) -> None:
    # A form's schema may only hold `type`, `properties` and `required` (MCP's
    # ElicitRequestFormParams). Pydantic adds a top-level `title`, and strict clients
    # such as Codex reject the whole form for it and cancel without showing a prompt.
    schema.pop("title", None)


# An empty form: the client's own Accept button is the confirmation. (No docstring, since
# it would become the schema description and some clients display it.)
class Confirmation(BaseModel):
    model_config = ConfigDict(json_schema_extra=_form_schema)


class _ClientCannotConfirm(Confirmation):
    """Returned by the resolver instead of a prompt when the client has no elicitation support."""


class _NotAsked(Confirmation):
    """Returned by the resolver when the call will be refused anyway, so the user isn't asked."""


def _holds_mask(value: Any) -> bool:
    if isinstance(value, str):
        return value == MASK
    if isinstance(value, dict):
        return any(_holds_mask(v) for v in value.values())
    if isinstance(value, list | tuple):
        return any(_holds_mask(v) for v in value)
    return False


class AuditSink(typing.Protocol):
    def write(self, entry: dict[str, Any]) -> Awaitable[None]: ...


class Guardrails:
    """Registers tools on an `MCPServer` under a `Policy`.

    `writer_check` (remote mode) decides from the signed-in user's token whether they may
    use write tools. `audit_sinks` receive every audit entry besides the policy's file.
    """

    def __init__(
        self,
        server: MCPServer,
        policy: Policy,
        *,
        writer_check: Callable[[AccessToken | None], bool] | None = None,
        audit_sinks: Sequence[AuditSink] = (),
    ) -> None:
        self._server = server
        self._policy = policy
        self._writer_check = writer_check
        self._audit_sinks = tuple(audit_sinks)
        self._registered: list[str] = []

    @property
    def registered(self) -> tuple[str, ...]:
        return tuple(self._registered)

    def read(self, *, name: str | None = None, title: str | None = None) -> Callable[[Callable], Callable]:
        """Register a tool that only reads. It is always available unless the policy denies it."""

        def decorator(fn: Callable) -> Callable:
            tool = name or fn.__name__
            if not self._policy.permits(tool):
                log.info("Tool %s not registered: excluded by policy", tool)
                return fn

            @functools.wraps(fn)
            async def run(*args: Any, **kwargs: Any) -> Any:
                return await self._call(tool, "read", fn, kwargs)

            self._server.add_tool(
                run, name=tool, title=title, annotations=ToolAnnotations(read_only_hint=True)
            )
            self._registered.append(tool)
            return fn

        return decorator

    def write(
        self,
        *,
        destructive: bool,
        confirm_message: str | None = None,
        idempotent: bool = False,
        name: str | None = None,
        title: str | None = None,
    ) -> Callable[[Callable], Callable]:
        """Register a tool that changes data. Only registered when writes are enabled.

        `confirm_message` is formatted with the tool's arguments, e.g.
        "Delete contact {contact_id}?". When omitted, a generic message lists the arguments.
        """

        def decorator(fn: Callable) -> Callable:
            tool = name or fn.__name__
            if not self._policy.writes_enabled:
                log.info("Tool %s not registered: writes are disabled", tool)
                return fn
            if not self._policy.permits(tool):
                log.info("Tool %s not registered: excluded by policy", tool)
                return fn

            kind = "destructive" if destructive else "write"
            needs_confirmation = self._policy.confirm == "all_writes" or (
                self._policy.confirm == "destructive" and destructive
            )
            if needs_confirmation:
                run = self._with_confirmation(tool, kind, fn, confirm_message)
            else:

                @functools.wraps(fn)
                async def run(*args: Any, **kwargs: Any) -> Any:
                    await self._refuse_non_writer(tool, kind, kwargs)
                    await self._refuse_masked(tool, kind, kwargs)
                    return await self._call(tool, kind, fn, kwargs)

            annotations = ToolAnnotations(
                read_only_hint=False, destructive_hint=destructive, idempotent_hint=idempotent
            )
            self._server.add_tool(run, name=tool, title=title, annotations=annotations)
            self._registered.append(tool)
            return fn

        return decorator

    def _with_confirmation(
        self, tool: str, kind: str, fn: Callable, message: str | None
    ) -> Callable:
        """Wrap `fn` so the SDK asks the user before the body runs.

        The SDK fills a parameter annotated `Resolve(resolver)` by running the resolver
        first. When the resolver returns `Elicit(...)`, the question travels to the client:
        as a multi-round-trip request on the 2026-07-28 protocol, or as a mid-call
        elicitation on older ones. The wrapper gets a synthetic signature (the tool's own
        parameters plus `confirmation`) because that is what the SDK introspects.
        """
        hints = typing.get_type_hints(fn, include_extras=True)
        # Use the resolved types, not the strings `from __future__ import annotations` leaves:
        # the SDK resolves strings against this module, where the tool's own names don't exist.
        params = [p.replace(annotation=hints.get(p.name, p.annotation)) for p in inspect.signature(fn).parameters.values()]
        tool_params = [p for p in params if hints.get(p.name) is not Context]
        if message:
            unknown = {f for _, f, _, _ in string.Formatter().parse(message) if f} - {p.name for p in tool_params}
            if unknown:
                raise ValueError(f"confirm_message for {tool} names unknown arguments: {sorted(unknown)}")

        def resolver(guardrails_ctx: Context, **arguments: Any) -> Any:
            if _holds_mask(arguments) or not self._may_write():
                return _NotAsked()
            capabilities = guardrails_ctx.client_capabilities
            if capabilities is None or capabilities.elicitation is None:
                return _ClientCannotConfirm()
            if message:
                text = message.format(**arguments)
            else:
                given = {k: v for k, v in arguments.items() if v is not None}  # skip unset optionals
                shown = ", ".join(f"{k}={v!r}" for k, v in mask(given, self._policy.mask_fields).items())
                text = f"Allow {tool}({shown})?"
            return Elicit(text, Confirmation)

        resolver.__signature__ = inspect.Signature(
            [inspect.Parameter("guardrails_ctx", inspect.Parameter.KEYWORD_ONLY, annotation=Context)]
            + [p.replace(kind=inspect.Parameter.KEYWORD_ONLY) for p in tool_params]
        )
        resolver.__annotations__ = {
            "guardrails_ctx": Context,
            **{p.name: hints[p.name] for p in tool_params if p.name in hints},
        }

        confirmation_type = Annotated[ElicitationResult[Confirmation], Resolve(resolver)]

        @functools.wraps(fn)
        async def run(*args: Any, confirmation: Any, **kwargs: Any) -> Any:
            await self._refuse_non_writer(tool, kind, kwargs)
            await self._refuse_masked(tool, kind, kwargs)
            if isinstance(getattr(confirmation, "data", None), _ClientCannotConfirm):
                await self._audit(tool, kind, kwargs, "blocked", 0.0)
                raise ToolError(
                    f"{tool} was not run: it needs the user's confirmation, and this connection can't "
                    "carry a confirmation prompt. Use a client that supports them, or set "
                    "`confirm: off` in the policy."
                )
            if isinstance(confirmation, CancelledElicitation):
                # Cancelled: the prompt was dismissed, or the client couldn't show it. Not
                # the same as the user saying no, so it's logged and reported separately.
                await self._audit(tool, kind, kwargs, "cancelled", 0.0)
                raise ToolError(f"{tool} was not run: the confirmation was cancelled (dismissed, or the client couldn't show it).")
            if not isinstance(confirmation, AcceptedElicitation):
                await self._audit(tool, kind, kwargs, "declined", 0.0)
                raise ToolError(f"{tool} was not run: the user declined.")
            return await self._call(tool, kind, fn, kwargs)

        del run.__wrapped__  # stop inspect from reading fn's signature instead of ours
        run.__signature__ = inspect.Signature(
            params + [inspect.Parameter("confirmation", inspect.Parameter.KEYWORD_ONLY, annotation=confirmation_type)],
            return_annotation=hints.get("return", inspect.Signature.empty),
        )
        run.__annotations__ = {**hints, "confirmation": confirmation_type}
        return run

    def _may_write(self) -> bool:
        return self._writer_check is None or self._writer_check(get_access_token())

    async def _refuse_non_writer(self, tool: str, kind: str, kwargs: dict[str, Any]) -> None:
        if not self._may_write():
            await self._audit(tool, kind, kwargs, "forbidden", 0.0)
            raise ToolError(
                f"{tool} was not run: your account doesn't have write access on this server. "
                "Ask the server's owner to grant you the writer role."
            )

    async def _refuse_masked(self, tool: str, kind: str, kwargs: dict[str, Any]) -> None:
        if _holds_mask(kwargs):
            await self._audit(tool, kind, kwargs, "refused", 0.0)
            raise ToolError(
                f"{tool} was not run: an argument is the placeholder {MASK!r}, which stands in for a "
                "hidden value. Pass only the fields you mean to change."
            )

    async def _call(self, tool: str, kind: str, fn: Callable, kwargs: dict[str, Any]) -> Any:
        started = time.perf_counter()
        try:
            if inspect.iscoroutinefunction(fn):
                result = await fn(**kwargs)
            else:
                # Same as the SDK does for plain tools: blocking clients don't stall the server.
                result = await anyio.to_thread.run_sync(functools.partial(fn, **kwargs))
        except Exception:
            await self._audit(tool, kind, kwargs, "error", time.perf_counter() - started)
            raise
        await self._audit(tool, kind, kwargs, "ok", time.perf_counter() - started)
        return mask(result, self._policy.mask_fields)

    async def _audit(self, tool: str, kind: str, arguments: dict[str, Any], outcome: str, seconds: float) -> None:
        path = self._policy.audit_path
        if path is None and not self._audit_sinks:
            return
        entry: dict[str, Any] = {
            "time": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "kind": kind,
            "outcome": outcome,
            "duration_ms": round(seconds * 1000, 1),
            "arguments": mask(
                {k: v for k, v in arguments.items() if not isinstance(v, Context)}, self._policy.mask_fields
            ),
        }
        token = get_access_token()
        if token is not None:
            entry["subject"] = token.subject
            entry["client_id"] = token.client_id
        if path is not None:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
            except OSError as exc:
                # Fail open: a full disk or bad path shouldn't take every tool down with it.
                # The error still reaches stderr, which MCP clients surface in their logs.
                log.error("Could not write audit log %s: %s", path, exc)
        for sink in self._audit_sinks:
            try:
                await sink.write(entry)
            except Exception:  # a sink's failure must never fail the tool call
                log.exception("Audit sink %s failed", type(sink).__name__)
