"""Safety layer for MCP tools.

Every tool is registered through `Guardrails.read` or `Guardrails.write`, which apply
four rules taken from the policy:

1. Write gate: write tools are not registered unless writes are enabled, so the model
   can't see them, let alone call them.
2. Allow/deny lists: a tool the policy rules out is never registered.
3. Confirmation: destructive calls pause and ask the user first. Clients that can't
   show a prompt are refused rather than allowed through.
4. Masking: fields such as `email` are replaced before a result reaches the model,
   and in the audit log. In free-text fields you name, email addresses and phone
   numbers inside the text are replaced in place. A write that passes the "[masked]"
   placeholder back is refused, so a model can't overwrite real data with it.

Each call is also appended to a JSON Lines audit log when one is configured, and sent to
any extra audit sinks (remote mode adds stderr and a Supabase table). Every entry names the
client by the name and version it reports for itself (and, over HTTP, its User-Agent). That is
untrusted text, kept to say which clients people use, and never used to decide anything.

The parts that don't need the SDK (the policy file, masking, the confirmation and refusal texts,
the audit log) are in `policy.py`. This module applies them to an `MCPServer`.

In remote mode a fifth rule applies: write tools also require the signed-in user's
writer role. It narrows what `<PREFIX>_ENABLE_WRITES` allows; it can never widen it.
"""

from __future__ import annotations

import contextvars
import functools
import inspect
import logging
import time
import typing
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Annotated, Any

import anyio.to_thread
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
from pydantic import BaseModel, ConfigDict

# The policy, masking, texts and audit log live in policy.py, which never imports the SDK. The
# names below are re-exported so everything that imported them from here keeps working.
from .policy import (
    _TRUTHY,
    MASK,
    MAX_CLIENT_TEXT,
    PATTERN_KINDS,
    AuditLog,
    AuditSink,
    ConfirmMode,
    PatternKind,
    Policy,
    PolicyError,
    _holds_mask,
    _untrusted,
    blocked_text,
    cancelled_text,
    check_confirm_message,
    confirm_text,
    declined_text,
    forbidden_text,
    mask,
    placeholder_text,
)

log = logging.getLogger(__name__)


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


@dataclass(frozen=True)
class _Client:
    name: str | None = None
    version: str | None = None
    user_agent: str | None = None


# Who is calling, for the audit log only. Set around each request by `_remember_client`.
_client: contextvars.ContextVar[_Client | None] = contextvars.ContextVar("client", default=None)


async def _remember_client(ctx: Any, call_next: Callable[[Any], Awaitable[Any]]) -> Any:
    """Middleware: note which client is calling, so audit rows can name it.

    The name and version are what the client says about itself: `clientInfo` in `initialize`
    (2025-11-25 and earlier) or in each request's `_meta` (2026-07-28). The SDK keeps both in
    `session.client_params`. Over stateless HTTP, a 2025-11-25 client's `initialize` is a request of
    its own, so later calls carry no name and only the User-Agent header is left. Everything here is
    untrusted text for the log, never an input to a decision.
    """
    try:
        params = ctx.session.client_params
        info = params.client_info if params is not None else None
        headers = getattr(ctx.request, "headers", None)
        client = _Client(
            _untrusted(getattr(info, "name", None)),
            _untrusted(getattr(info, "version", None)),
            _untrusted(headers.get("user-agent")) if headers is not None else None,
        )
    except Exception:  # noting the client must never fail the call
        log.exception("Could not read the client's name")
        client = _Client()
    token = _client.set(client)
    try:
        return await call_next(ctx)
    finally:
        _client.reset(token)


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
        self._audit_log = AuditLog(policy, audit_sinks)
        self._registered: list[str] = []
        if _remember_client not in server.middleware:  # once, however many Guardrails share a server
            server.middleware.append(_remember_client)

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
            check_confirm_message(tool, message, {p.name for p in tool_params})

        def resolver(guardrails_ctx: Context, **arguments: Any) -> Any:
            if _holds_mask(arguments, self._policy.mask_pattern_fields) or not self._may_write():
                return _NotAsked()
            capabilities = guardrails_ctx.client_capabilities
            if capabilities is None or capabilities.elicitation is None:
                return _ClientCannotConfirm()
            return Elicit(confirm_text(self._policy, tool, message, arguments), Confirmation)

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
                raise ToolError(blocked_text(tool))
            if isinstance(confirmation, CancelledElicitation):
                # Cancelled: the prompt was dismissed, or the client couldn't show it. Not
                # the same as the user saying no, so it's logged and reported separately.
                await self._audit(tool, kind, kwargs, "cancelled", 0.0)
                raise ToolError(cancelled_text(tool))
            if not isinstance(confirmation, AcceptedElicitation):
                await self._audit(tool, kind, kwargs, "declined", 0.0)
                raise ToolError(declined_text(tool))
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
            raise ToolError(forbidden_text(tool))

    async def _refuse_masked(self, tool: str, kind: str, kwargs: dict[str, Any]) -> None:
        if _holds_mask(kwargs, self._policy.mask_pattern_fields):
            await self._audit(tool, kind, kwargs, "refused", 0.0)
            raise ToolError(placeholder_text(tool))

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
        return self._policy.mask(result)

    async def _audit(self, tool: str, kind: str, arguments: dict[str, Any], outcome: str, seconds: float) -> None:
        if not self._audit_log.enabled:
            return
        extra: dict[str, Any] = {}
        token = get_access_token()
        if token is not None:
            extra["subject"] = token.subject
            extra["client_id"] = token.client_id
        client = _client.get()
        if client is not None:  # what the client says about itself; absent when it said nothing
            for key, value in (("client_name", client.name), ("client_version", client.version), ("user_agent", client.user_agent)):
                if value:
                    extra[key] = value
        shown = {k: v for k, v in arguments.items() if not isinstance(v, Context)}
        await self._audit_log.record(tool, kind, shown, outcome, seconds, extra)
