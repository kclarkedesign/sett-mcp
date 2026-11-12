"""Read-only look at the FastMCP 4 API surface the spike depends on."""

import inspect

import fastmcp
from fastmcp import Client, Context, FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools import InputRequiredToolResult, ToolResult

print("fastmcp", fastmcp.__version__)

print("\n== InputRequiredToolResult.__init__ ==")
print(inspect.signature(InputRequiredToolResult.__init__))

for modname in ("mcp_types", "mcp.types"):
    try:
        mod = __import__(modname, fromlist=["x"])
    except ImportError as exc:
        print(f"\n{modname}: not importable ({exc})")
        continue
    print(f"\n== {modname} ==")
    for name in ("InputRequiredResult", "ElicitRequest", "ElicitRequestFormParams", "ElicitResult"):
        cls = getattr(mod, name, None)
        print(name, "->", "missing" if cls is None else list(getattr(cls, "model_fields", {}).keys()))

print("\n== Context: members mentioning input/request_state/capab/elicit/protocol ==")
for n in sorted(dir(Context)):
    if any(k in n.lower() for k in ("input", "request_state", "capab", "elicit", "protocol", "support")):
        attr = inspect.getattr_static(Context, n)
        kind = "property" if isinstance(attr, property) else type(attr).__name__
        print(f"  {n}  [{kind}]")

print("\n== Context.elicit signature ==")
print(inspect.signature(Context.elicit))

print("\n== Middleware hooks ==")
print([n for n in dir(Middleware) if n.startswith("on_")])

print("\n== MiddlewareContext fields ==")
print(list(getattr(MiddlewareContext, "__dataclass_fields__", {}).keys()))

print("\n== Client.__init__ params ==")
print(list(inspect.signature(Client.__init__).parameters))

print("\n== FastMCP.__init__ params mentioning state/security/middleware ==")
print([p for p in inspect.signature(FastMCP.__init__).parameters if any(k in p for k in ("state", "security", "middleware"))])

from mcp.server.request_state import RequestStateSecurity

print("\n== RequestStateSecurity ==")
print(inspect.signature(RequestStateSecurity.__init__))
print([n for n in dir(RequestStateSecurity) if not n.startswith("_")])
