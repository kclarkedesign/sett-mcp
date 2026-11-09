"""`sett-mcp new`, `update` and `check`.

    uvx sett-mcp new my-server                         # Copier, pointed at the Sett template
    cd my-server && uvx sett-mcp update
    uvx sett-mcp check https://my-server.vercel.app/mcp  # test a deployed server before sharing it
"""

from __future__ import annotations

import argparse
import sys

import copier

from sett_mcp import __version__

TEMPLATE = "gh:kclarkedesign/sett-mcp"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="sett-mcp", description="Create Python MCP servers that are read-only until you say otherwise."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    new = commands.add_parser("new", help="create a new MCP server project")
    new.add_argument("directory", help="where to create the project, e.g. my-server")
    new.add_argument("--defaults", action="store_true", help="use default answers instead of asking")
    new.add_argument("-d", "--data", action="append", default=[], metavar="KEY=VALUE", help="answer a question up front")

    update = commands.add_parser("update", help="pull template changes into an existing project")
    update.add_argument("directory", nargs="?", default=".", help="project to update (default: current folder)")
    update.add_argument("--defaults", action="store_true", help="keep previous answers without asking")

    check = commands.add_parser("check", help="test a deployed MCP server the way clients will")
    check.add_argument("url", help="the server's MCP address, e.g. https://my-server.vercel.app/mcp")
    check.add_argument("--token", help="an access token, to check the tools too (`-` asks for it instead)")

    for command in (new, update):
        command.add_argument("--ref", help="template version (git tag or branch); default: latest release")
        command.add_argument("--template", default=TEMPLATE, help=argparse.SUPPRESS)  # for testing

    args = parser.parse_args(argv)
    if args.command == "check":
        import getpass

        from sett_mcp.check import check as run_check
        from sett_mcp.check import report

        token = getpass.getpass("Access token: ").strip() if args.token == "-" else args.token
        sys.exit(report(run_check(args.url, token=token or None)))
    try:
        if args.command == "new":
            data = dict(_pair(item) for item in args.data)
            copier.run_copy(args.template, args.directory, data, defaults=args.defaults, vcs_ref=args.ref)
        else:
            copier.run_update(args.directory, defaults=args.defaults, overwrite=True, vcs_ref=args.ref)
    except KeyboardInterrupt:
        sys.exit(130)


def _pair(item: str) -> tuple[str, str]:
    key, sep, value = item.partition("=")
    if not sep:
        raise SystemExit(f"--data expects KEY=VALUE, got {item!r}")
    return key, value
