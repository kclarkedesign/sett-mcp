# Migrating a FastMCP v1 server to SDK v2

Python SDK v2.0.0 shipped on July 28, 2026 alongside the 2026-07-28 spec. v1.x now gets security fixes only. This guide covers what a typical `FastMCP` tool server has to change, and how to move a hand-rolled write gate onto this template's guardrails. The [official migration guide](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/migration.md) covers everything else, including the lowlevel `Server` and client code.

## Checklist

| v1 | v2 | Symptom if you miss it |
|---|---|---|
| `mcp[cli]>=1` | `mcp>=2.2,<3` | resolver conflicts on anyio, pydantic, sse-starlette |
| `from mcp.server.fastmcp import FastMCP` | `from mcp.server.mcpserver import MCPServer, Context` | `ModuleNotFoundError: mcp.server.fastmcp` |
| `FastMCP("Demo", port=8000)` | `MCPServer("Demo")`, then `run("streamable-http", port=8000)` | `TypeError: unexpected keyword argument 'port'` |
| `mcp.get_context()` inside a tool | add a `ctx: Context` parameter | `AttributeError` |
| `ctx.fastmcp` | `ctx.mcp_server` | `AttributeError` |
| `from mcp.server.fastmcp.exceptions import ToolError` | `from mcp.server.mcpserver.exceptions import ToolError` | `ModuleNotFoundError` |
| `McpError` | `MCPError` | `ImportError` |
| `tool.inputSchema`, `result.isError` (tests, clients) | `tool.input_schema`, `result.is_error` | `AttributeError` |
| relying on the SDK to pull in `httpx` | add `httpx` to your own dependencies (the SDK now uses `httpx2`) | `ModuleNotFoundError: httpx` |
| `MCP_*` environment variables | read the environment yourself | settings silently ignored |

## Behavior changes worth knowing

- **Sync tools run on a worker thread.** A `def` tool using a blocking client (a synchronous SDK for your API, say) no longer stalls the whole server. Keep shared clients thread-safe, or make the tool `async def`.
- **`MCPError` raised in a tool is now a protocol error.** For failures the model should see and react to ("no contact with that id"), raise `ToolError`; the model gets an `is_error` result with your message.
- **Elicitation needs the client's declared capability on every protocol version.** v1 would send a prompt to any client; v2 fails the call instead. The template turns that into a clear refusal rather than an error.
- **The SDK client defaults to `mode="auto"`** and probes `server/discover`. Test harnesses that assert on exact messages may need `mode="legacy"`.

## Moving a write gate onto the guardrails

A common v1 pattern registers write tools only when an environment flag is set:

```python
# v1
mcp = FastMCP("Inventory")

@mcp.tool()
def inv_lookup(sku: str) -> dict:
    ...

if os.environ.get("INV_ENABLE_WRITES") == "true":
    @mcp.tool()
    def inv_delete_item(item_id: str) -> str:
        ...
```

With the template, the gate, confirmation, hints, masking and audit come from the decorator:

```python
# v2 with Sett
@guard.read(name="inv_lookup")
def inv_lookup(sku: str) -> dict:
    ...

@guard.write(
    name="inv_delete_item",
    destructive=True,
    confirm_message="Delete item {item_id}? This can't be undone.",
)
def inv_delete_item(item_id: str) -> dict:
    ...
```

`INV_ENABLE_WRITES` keeps working if you generate the project with `env_prefix: INV`. If your server also has a platform-side safeguard, such as a read-only role on its service account, keep it: the guardrails are one layer, not a replacement for least-privilege credentials.
