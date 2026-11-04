<p align="center">
  <img src="assets/sett-reveal.svg#gh-light-mode-only" alt="Sett" width="480">
  <img src="assets/sett-reveal-white.svg#gh-dark-mode-only" alt="Sett" width="480">
</p>

**Python MCP servers that are read-only until you say otherwise.** One command gives you a working server on the official MCP Python SDK v2, with guardrails that are tested and on by default.

[![Test template](https://github.com/kclarkedesign/sett-mcp/actions/workflows/test-template.yml/badge.svg)](https://github.com/kclarkedesign/sett-mcp/actions/workflows/test-template.yml)

```bash
uvx sett-mcp new my-server
```

*A sett is a badger's den, dug deep and hard to break into. Setts are also the square stones that pave a solid road.*

<!-- demo GIF: Claude searching contacts (masked), then a delete that asks for confirmation -->

## Why

Connecting an AI assistant to a real system is easy. Being comfortable leaving it connected is the hard part: what happens when the model decides to "clean up" some records? Most MCP starters give you a tool decorator and leave the rest to you. This one starts from the question your ops or security lead will ask.

## What you get

| Guardrail | How it works |
|---|---|
| **Write gate** | Write tools aren't registered unless `<PREFIX>_ENABLE_WRITES=true`. The model can't call what it can't see. The policy file can't flip this; only whoever runs the server can. |
| **Confirmations** | Destructive tools ask the user first ("Permanently delete contact c001?"), using multi-round-trip requests on the 2026-07-28 protocol and elicitation on older ones. Clients that can't show a prompt are refused, not waved through. See [client support](#client-support). |
| **Allow / deny lists** | Tools the policy excludes are never registered. |
| **Field masking** | `email`, `phone` or any field you list becomes `[masked]` before results reach the model or the audit log. A write that passes `[masked]` back is refused, so the placeholder can't overwrite real data. |
| **Audit log** | One JSON line per call: tool, kind, outcome, duration, masked arguments. |
| **Tool hints** | Every tool is marked read-only or destructive so clients can warn users. |
| **Strict policy file** | Unknown keys fail at startup, so a typo can't silently turn masking off. |

Plus the plumbing that usually takes an afternoon:

- A runnable example (a small contacts store) you replace with your real API client
- `install-claude-desktop` command that writes the config for macOS, Windows and Linux
- Stdio by default, stateless Streamable HTTP with `serve --http`
- Tests that drive the server through a real MCP client on both protocol versions
- GitHub Actions for CI and PyPI publishing, so users can run `uvx your-server`
- A `CLAUDE.md` that keeps Claude Code from bypassing the guardrails when it adds tools

## Quick start

```bash
uvx sett-mcp new my-server
cd my-server
uv run --extra dev pytest                  # the guardrail test suite
uv run my-server install-claude-desktop    # then restart Claude Desktop
```

Copier asks for a name, tool prefix and environment-variable prefix. Everything else is filled in.

Adding a tool looks like this:

```python
@guard.read(name="acme_list_invoices")
async def list_invoices(status: str = "open") -> list[dict]:
    """List invoices by status."""
    return await api.invoices(status=status)

@guard.write(name="acme_void_invoice", destructive=True,
             confirm_message="Void invoice {invoice_id}? This can't be undone.")
async def void_invoice(invoice_id: str) -> dict:
    """Void an invoice."""
    return await api.void(invoice_id)
```

## Client support

Tested in November 2026 with the example server this template generates:

| Client | Tools and masking | Confirmation prompts |
|---|---|---|
| Claude Code | ✅ | ✅ Shows an Accept / Decline prompt, including in auto mode |
| Claude Desktop 4.x (Windows) | ✅ | ⛔ No prompt shown, so tools that need confirmation are refused and nothing changes |
| Cursor | Not tested yet | Not tested yet |

What that means in practice:

- **A confirmation is only as strong as the client.** Sett can't tell a person clicking Accept from a client that accepts automatically. The write gate and the allow / deny lists don't depend on the client at all, so treat those as the hard limits.
- **In clients without prompts,** keep the default `confirm: destructive`. Ordinary writes still work, and destructive ones are refused. Setting `confirm: off` makes them run without asking.
- **Claude may refuse on its own.** In our tests Claude sometimes declined to call a tool described as permanently deleting data, or asked in chat first. That's a welcome extra layer, but it depends on the model and the conversation, which is why the server enforces confirmation itself.

Tried another client? Open an issue with what you saw and we'll add it to the table.

## Keeping generated projects current

Guardrail fixes and SDK updates land here. Pull them into any project made from the template with:

```bash
uvx sett-mcp update
```

`sett-mcp` is a thin wrapper around [Copier](https://copier.readthedocs.io), so `uvx copier copy gh:kclarkedesign/sett-mcp my-server` and `copier update` work too.

## Migrating from FastMCP v1

SDK v2 renamed `FastMCP` to `MCPServer` and changed a dozen other things. See [docs/migrating-from-v1.md](docs/migrating-from-v1.md) for the checklist and how to move a hand-rolled write gate onto the guardrails.

## Roadmap

- **Remote in one command:** `deploy vercel --auth supabase`, which hosts the server on your own Vercel project with Supabase handling OAuth, and write access tied to user roles
- One-click `.mcpb` bundles for Claude Desktop
- Cloudflare Workers deploy target
- Example connectors, starting with a read-only Salesforce analyst server

## Contributing

Issues and pull requests are welcome. To work on the template itself:

```bash
uvx copier copy --trust --defaults --vcs-ref HEAD . /tmp/check
cd /tmp/check && uv run --extra dev pytest
```

## License

Apache-2.0. Projects you generate can choose Apache-2.0 or MIT. Logo and icon files are in `assets/`, including an animated reveal and a looping loading mark (rebuild them with `node scripts/build_motion.mjs`).
