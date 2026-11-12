"""Can this client show our confirmation form? (Codex review of PR #27, finding P2.)

Presence of `elicitation` is not enough: a client may declare only `url`, and the spec
(2026-07-28, client/elicitation) says an empty `elicitation: {}` means form mode only.
This checks the predicate against the SDK's real capability models, and shows what the
SDK's own `check_capability` says (it only looks at presence).
"""

from types import SimpleNamespace

from mcp.server.connection import Connection
from mcp_types import ClientCapabilities, ElicitationCapability


def can_show_form(caps: ClientCapabilities | None) -> bool:
    e = None if caps is None else caps.elicitation
    # An empty `elicitation` object (neither form nor url) means form only.
    return e is not None and (e.form is not None or e.url is None)


CASES = [
    ("no capabilities at all (None)", None, False),
    ("capabilities without `elicitation`", ClientCapabilities.model_validate({}), False),
    ('`elicitation: {}` (form, by the backward-compat rule)', ClientCapabilities.model_validate({"elicitation": {}}), True),
    ("form only", ClientCapabilities.model_validate({"elicitation": {"form": {}}}), True),
    ("url only", ClientCapabilities.model_validate({"elicitation": {"url": {}}}), False),
    ("form and url", ClientCapabilities.model_validate({"elicitation": {"form": {}, "url": {}}}), True),
]

failed = 0
for label, caps, expected in CASES:
    got = can_show_form(caps)
    ok = got == expected
    failed += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] can_show_form: {label}: got {got}, expected {expected}")

# What the SDK's own check says for a URL-only client (it should say True: presence only).
url_only = ClientCapabilities.model_validate({"elicitation": {"url": {}}})
sdk_says = Connection.check_capability(
    SimpleNamespace(client_capabilities=url_only), ClientCapabilities(elicitation=ElicitationCapability())
)
print(f"[INFO] SDK check_capability(elicitation) for a URL-only client: {sdk_says} (True = it would let them through)")
raise SystemExit(1 if failed else 0)
