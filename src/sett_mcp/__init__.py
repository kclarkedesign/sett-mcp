"""Create safe-by-default Python MCP servers from the Sett template."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sett-mcp")  # set from the git tag at build time (see pyproject.toml)
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0"
