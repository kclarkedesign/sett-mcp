"""Second read-only look: raw-round driving and client-capability access."""

import inspect

from fastmcp import Client, Context

print("== fastmcp Client: call-ish methods ==")
for n in ("call_tool", "call_tool_mcp", "list_tools", "list_tools_mcp"):
    fn = getattr(Client, n, None)
    print(f"{n}:", "missing" if fn is None else inspect.signature(fn))

print("\n== fastmcp Client members mentioning session/raw/round/input ==")
print([n for n in dir(Client) if any(k in n.lower() for k in ("session", "raw", "round", "input", "mrtr", "state"))])

print("\n== Context members: session/request_context/ctx accessors ==")
print([n for n in dir(Context) if any(k in n.lower() for k in ("session", "request_context", "request_id", "client"))])

from mcp.server.session import ServerSession

print("\n== SDK ServerSession members mentioning capab/elicit/client ==")
print([n for n in dir(ServerSession) if any(k in n.lower() for k in ("capab", "elicit", "client_params", "protocol"))])
print("check_client_capability:", inspect.signature(ServerSession.check_client_capability))

try:
    from mcp import Client as SdkClient

    print("\n== SDK mcp.Client.call_tool ==")
    print(inspect.signature(SdkClient.call_tool))
    print([n for n in dir(SdkClient) if any(k in n.lower() for k in ("input", "request_state", "round", "send"))])
except ImportError as exc:
    print("mcp.Client not importable:", exc)
