"""The framework-free half of the guardrails: the policy file, masking, the texts people read, and the audit log.

Nothing here imports the MCP SDK, so a layer for another framework can reuse this file as it is.
`guardrails.py` applies it to an `MCPServer` and re-exports these names.

- `Policy` loads the YAML policy and the environment (`<PREFIX>_ENABLE_WRITES` is the only way to
  turn writes on) and answers "may this tool run?" and "what may the model see?".
- `mask` hides fields, and the email addresses and phone numbers inside free-text fields.
- `confirm_text`, `CONFIRM_FORM` and the `*_text` functions are what the user is asked and what the
  caller is told, so every layer says the same thing.
- `AuditLog` writes one entry per call to the policy's JSON Lines file and to any `AuditSink`.
"""

from __future__ import annotations

import json
import logging
import os
import re
import string
import typing
from collections.abc import Awaitable, Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError

log = logging.getLogger(__name__)

MASK = "[masked]"
ConfirmMode = Literal["destructive", "all_writes", "off"]
PatternKind = Literal["email", "phone"]
PATTERN_KINDS: tuple[PatternKind, ...] = ("email", "phone")
_TRUTHY = {"1", "true", "yes", "on"}


class PolicyError(ValueError):
    """The policy file is missing, malformed or contains unknown keys."""


def _clean_names(names: list[str]) -> list[str]:
    # A blank name matches nothing, and so does a name with stray spaces. Quietly, which is worst
    # in `deny` (the tool stays registered) and `mask_fields` (the field stays visible).
    names = [name.strip() for name in names]
    if not all(names):
        raise ValueError("names can't be blank")
    return names


# A list of tool or field names from the policy file: stripped, and refused if any is blank.
_Names = Annotated[list[str], AfterValidator(_clean_names)]


class _ToolLists(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allow: _Names | None = None
    deny: _Names = []


class _Audit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str | None = None


class _MaskPatterns(BaseModel):
    # Both lists must name something: an empty one would be a policy that quietly hides nothing.
    model_config = ConfigDict(extra="forbid")
    fields: _Names = Field(min_length=1)
    kinds: list[PatternKind] = Field(default_factory=lambda: list(PATTERN_KINDS), min_length=1)


class _PolicyFile(BaseModel):
    # extra="forbid" turns a typo like `mask_feilds` into a startup error instead of a
    # silently unmasked field. It also means the file cannot carry a `writes` key:
    # enabling writes is deliberately an environment decision, made by whoever runs
    # the server, not a line someone can commit to the repo.
    model_config = ConfigDict(extra="forbid")
    confirm: ConfirmMode = "destructive"
    tools: _ToolLists = _ToolLists()
    mask_fields: _Names = []
    mask_patterns: _MaskPatterns | None = None
    audit: _Audit = _Audit()


@dataclass(frozen=True)
class Policy:
    writes_enabled: bool = False
    confirm: ConfirmMode = "destructive"
    allow: frozenset[str] | None = None
    deny: frozenset[str] = frozenset()
    mask_fields: frozenset[str] = frozenset()
    audit_path: Path | None = None
    # Free-text fields whose email addresses and phone numbers are hidden in place (see `mask`).
    mask_pattern_fields: frozenset[str] = frozenset()
    mask_pattern_kinds: frozenset[str] = frozenset(PATTERN_KINDS)

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
        patterns = parsed.mask_patterns
        return cls(
            writes_enabled=writes_enabled,
            confirm=parsed.confirm,
            allow=frozenset(parsed.tools.allow) if parsed.tools.allow else None,
            deny=frozenset(parsed.tools.deny),
            mask_fields=frozenset(f.lower() for f in parsed.mask_fields),
            audit_path=Path(parsed.audit.path).expanduser() if parsed.audit.path else None,
            mask_pattern_fields=frozenset(f.lower() for f in patterns.fields) if patterns else frozenset(),
            mask_pattern_kinds=frozenset(patterns.kinds) if patterns else frozenset(PATTERN_KINDS),
        )

    def permits(self, tool: str) -> bool:
        return tool not in self.deny and (self.allow is None or tool in self.allow)

    def mask(self, value: Any) -> Any:
        """`value` as the model may see it: masked fields replaced, personal data hidden in the pattern fields."""
        return mask(value, self.mask_fields, self.mask_pattern_fields, self.mask_pattern_kinds)

    def message_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """The arguments a custom `confirm_message` is formatted from.

        Email addresses and phone numbers in the pattern-masked fields are hidden here too, wherever
        they sit (an argument of that name, or inside a structured one), so the prompt can't show what
        results and the audit log hide. Everything else is shown as the tool's author wrote the message
        to show it. (A message may only use bare argument names, so a model turned into a dict is safe.)
        """
        return mask(arguments, frozenset(), self.mask_pattern_fields, self.mask_pattern_kinds)


def _read_policy_text(path: Path) -> str:
    try:
        return path.read_text()
    except OSError as exc:
        raise PolicyError(f"Cannot read policy file {path}: {exc}") from exc


# The built-in patterns are deliberately conservative: a missed number is a known limit (the docs say
# so), while hiding an order number hides something the model may need. They are bounded, so a long
# run of look-alike characters can't make the scan slow.
_EMAIL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+\-']{0,63}@(?:[A-Za-z0-9\-]{1,63}\.)+[A-Za-z]{2,24}")
# Phone numbers are matched by the shapes people write them in, not by "some digits": 555-0101,
# 555.010.1234, (555) 010-1234, 1-800-555-0101, +1 555 010 1234, +44 20 7946 0958, +15550101234.
# So ids and dates (4471-2290, 2026-0042, 2026-11-11, 94103-1234) and plain digit runs are left alone.
_PHONE = re.compile(
    r"(?<![\w.\-+])"  # not the tail of a longer token, number or reference
    r"(?:\+\d{8,15}"  # +15550101234
    r"|\+\d{1,3}(?:(?:[ .\-]|(?<=\)))\(?\d{1,4}\)?){2,6}"  # +44 20 7946 0958, +1 (555) 010-1234
    r"|(?:1[ .\-])?(?:\(\d{3}\)[ .\-]?|\d{3}[ .\-])\d{3}[ .\-]\d{4}"  # (555) 010-1234, 555.010.1234, 1-800-555-0101
    r"|\d{3}[ .\-]\d{4})"  # 555-0101
    r"(?!\w|[.\-]\d)"  # nor the start of a longer one
)


def _hide_phone(found: re.Match[str]) -> str:
    text = found.group()
    return MASK if 7 <= sum(char.isdigit() for char in text) <= 15 else text  # E.164 numbers have at most 15 digits


def _scan(text: str, kinds: frozenset[str]) -> str:
    """`text` with the email addresses and phone numbers (as far as `kinds` asks) replaced in place."""
    if "email" in kinds and "@" in text:
        text = _EMAIL.sub(MASK, text)
    if "phone" in kinds:
        text = _PHONE.sub(_hide_phone, text)
    return text


def mask(
    value: Any,
    fields: frozenset[str],
    text_fields: frozenset[str] = frozenset(),
    kinds: frozenset[str] = frozenset(),
) -> Any:
    """Hide what the policy says the model must not see, anywhere in a nested result.

    The values of `fields` (case-insensitive) are replaced whole. In `text_fields`, only the email
    addresses and phone numbers (`kinds`) inside the text are replaced, so the rest stays readable.
    A field in both is replaced whole. Empty values (None) are left alone, so "not set" doesn't
    read as "hidden".
    """
    scan = bool(text_fields and kinds)
    if not fields and not scan:
        return value
    return _mask(value, fields, text_fields if scan else frozenset(), kinds, False)


def _mask(value: Any, fields: frozenset[str], text_fields: frozenset[str], kinds: frozenset[str], scanning: bool) -> Any:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {
            k: MASK
            if str(k).lower() in fields and v is not None
            else _mask(v, fields, text_fields, kinds, scanning or str(k).lower() in text_fields)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [_mask(v, fields, text_fields, kinds, scanning) for v in value]
    if scanning and isinstance(value, str):
        return _scan(value, kinds)
    return value


def _holds_mask(value: Any, text_fields: frozenset[str] = frozenset(), scanning: bool = False) -> bool:
    """Whether a write hands the placeholder back: a value that is `[masked]`, or, in a pattern-masked
    field, text that contains it. Writing it would overwrite the real value (or the real text) with it."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if isinstance(value, str):
        return value == MASK or (scanning and MASK in value)
    if isinstance(value, Mapping):
        return any(_holds_mask(v, text_fields, scanning or str(k).lower() in text_fields) for k, v in value.items())
    if isinstance(value, list | tuple):
        return any(_holds_mask(v, text_fields, scanning) for v in value)
    return False


# The confirmation prompt: an empty form, so the client's own Accept button is the confirmation. It
# carries no `title` or `description`, because strict clients such as Codex reject the whole form for
# a `title` and cancel without showing a prompt, and some clients display a description.
CONFIRM_FORM: dict[str, Any] = {"type": "object", "properties": {}}


def check_confirm_message(tool: str, message: str, names: Collection[str]) -> None:
    """Fail at startup if a tool's `confirm_message` uses a name that isn't one of its arguments."""
    unknown = {f for _, f, _, _ in string.Formatter().parse(message) if f} - set(names)
    if unknown:
        raise ValueError(f"confirm_message for {tool} names unknown arguments: {sorted(unknown)}")


def confirm_text(policy: Policy, tool: str, message: str | None, arguments: Mapping[str, Any]) -> str:
    """What the user is asked: the tool's own `confirm_message` filled in, or a generic line listing the arguments."""
    if message:
        return message.format(**policy.message_arguments(dict(arguments)))
    given = {k: v for k, v in arguments.items() if v is not None}  # skip unset optionals
    shown = ", ".join(f"{k}={v!r}" for k, v in policy.mask(given).items())
    return f"Allow {tool}({shown})?"


def blocked_text(tool: str) -> str:
    return (
        f"{tool} was not run: it needs the user's confirmation, and this connection can't "
        "carry a confirmation prompt. Use a client that supports them, or set "
        "`confirm: off` in the policy."
    )


def cancelled_text(tool: str) -> str:
    # Not the same as the user saying no: the prompt was dismissed, or the client couldn't show it.
    return f"{tool} was not run: the confirmation was cancelled (dismissed, or the client couldn't show it)."


def declined_text(tool: str) -> str:
    return f"{tool} was not run: the user declined."


def forbidden_text(tool: str) -> str:
    return (
        f"{tool} was not run: your account doesn't have write access on this server. "
        "Ask the server's owner to grant you the writer role."
    )


def placeholder_text(tool: str) -> str:
    return (
        f"{tool} was not run: an argument is, or contains, the placeholder {MASK!r}, which stands in "
        "for a hidden value. Pass only the fields you mean to change, with their real text."
    )


class AuditSink(typing.Protocol):
    def write(self, entry: dict[str, Any]) -> Awaitable[None]: ...


MAX_CLIENT_TEXT = 200


def _untrusted(value: object) -> str | None:
    """Text a client chose for itself, made safe to keep: printable, on one line, at most 200 characters.

    A client can call itself anything. Control characters and lone surrogates would make Postgres
    refuse the whole audit row, which would let a client keep its own calls out of the log.
    """
    if not isinstance(value, str):
        return None
    text = " ".join("".join(c if c.isprintable() else " " for c in value[: MAX_CLIENT_TEXT * 4]).split())
    return text[:MAX_CLIENT_TEXT] or None


class AuditLog:
    """One entry per tool call, to the policy's JSON Lines file and to each sink.

    The caller passes `extra` (who is calling: subject, client_id, client_name, ...), because each
    framework finds that in a different place.
    """

    def __init__(self, policy: Policy, sinks: Sequence[AuditSink] = ()) -> None:
        self._policy = policy
        self._sinks = tuple(sinks)

    @property
    def enabled(self) -> bool:
        return self._policy.audit_path is not None or bool(self._sinks)

    async def record(
        self,
        tool: str,
        kind: str,
        arguments: dict[str, Any],
        outcome: str,
        seconds: float,
        extra: Mapping[str, Any] | None = None,
    ) -> None:
        if not self.enabled:
            return
        entry: dict[str, Any] = {
            "time": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "kind": kind,
            "outcome": outcome,
            "duration_ms": round(seconds * 1000, 1),
            "arguments": self._policy.mask(arguments),
        }
        for key, value in (extra or {}).items():
            if key in entry:  # an extra must never replace a canonical field, least of all the masked arguments
                log.warning("Audit extra %r ignored: the entry already has that field", key)
            else:
                entry[key] = value
        path = self._policy.audit_path
        if path is not None:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
            except OSError as exc:
                # Fail open: a full disk or bad path shouldn't take every tool down with it.
                # The error still reaches stderr, which MCP clients surface in their logs.
                log.error("Could not write audit log %s: %s", path, exc)
        for sink in self._sinks:
            try:
                await sink.write(entry)
            except Exception:  # a sink's failure must never fail the tool call
                log.exception("Audit sink %s failed", type(sink).__name__)
