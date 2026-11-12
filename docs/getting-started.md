# Getting started with Sett

This guide goes from nothing installed to an MCP server you can talk to from Claude, Cursor or Codex, in about 15 minutes. Every command has a Windows (PowerShell) and a macOS / Linux version where they differ. If something goes wrong before your project exists, see [the table at the end](#before-your-project-exists-common-problems). After that, every project has its own `docs/troubleshooting.md`, with your project's names already in the commands, covering what people actually run into.

## 1. Install uv

[uv](https://docs.astral.sh/uv/) runs Python projects without you managing Python or virtualenvs. It's the only thing Sett needs.

| | Command |
|---|---|
| Windows | `winget install --id=astral-sh.uv -e` |
| macOS / Linux | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

Then **close the terminal and open a new one**, so it picks up the new `uv` command. Check it with `uv --version`.

## 2. Create a project

```bash
uvx sett-mcp new my-server
```

`uvx` downloads Sett, runs it once and leaves nothing installed. It asks 11 questions; press Enter to keep a default. The ones that matter:

| Question | Example | What it becomes |
|---|---|---|
| Name | `Billing MCP` | What clients display |
| Package and command name | `billing-mcp` | The command you run: `uv run billing-mcp` |
| Tool prefix | `billing` | Tool names: `billing_search_contacts` |
| Environment-variable prefix | `BILLING_MCP` | Settings: `BILLING_MCP_ENABLE_WRITES` |

The rest of this guide uses `my-server` for the command and `MY_SERVER` for the prefix. Use yours.

## 3. Check it works

```bash
cd my-server
uv sync
uv run --extra dev pytest
```

`uv sync` installs the project (the first time takes a minute). The tests start a real MCP client against your server, so a green run means the server works before you connect anything.

## 4. Connect a client

One command per client. Each one backs up the client's config file before changing it.

```bash
uv run my-server install claude-desktop
uv run my-server install cursor
uv run my-server install claude-code
uv run my-server install codex
uv run my-server install all          # every client it finds
```

Then restart the client. For **Claude Desktop that means a full quit**: closing the window leaves it running. On Windows, right-click its icon in the system tray (bottom right, maybe behind the ^ arrow) and choose Quit; on macOS, Claude > Quit Claude. Then open it again.

Try it: ask *"Search my contacts for Ada."* The example server holds a few sample contacts; emails and phone numbers come back as `[masked]`.

## 5. Turn on writes (when you want them)

Out of the box the server is read-only: the write tools don't exist, so the model can't call them. To turn them on for a client, install again with `--writes`:

```bash
uv run my-server install claude-desktop --writes
```

Restart the client, then try *"Update contact c001's company to Harbor."* Deletes ask you first, in clients that can show a prompt (see the [client support table](../README.md#client-support)). To turn writes off again, install without `--writes`.

To take the server out of a client: `uv run my-server install cursor --remove`.

## 6. Make it yours

Replace the sample contacts with your real API in `src/<your_package>/tools.py`. The project's `CLAUDE.md` tells Claude Code how to add tools without bypassing the guardrails, so asking Claude Code to "add a tool that lists invoices" is a good way to start.

## 7. Share it with your team

When others should use it, deploy it with sign-in on your own Vercel and Supabase accounts:

```bash
uv run my-server deploy vercel --auth supabase --create-supabase-project --writes
uv run my-server users add you@example.com --writer      # several at once: ada@example.com bob@example.com
```

Before sharing the address, test it the way clients will: `uvx sett-mcp check https://<your-project>.vercel.app/mcp`. It prints one line per check (PASS, WARN, FAIL or INFO) and a fix under each WARN or FAIL. If a FAIL isn't clear, your project's `docs/troubleshooting.md` has a "Testing a deployed server" section that explains the common ones, such as a sign-in that answers 403 instead of 401.

Then, in claude.ai: **Settings, Connectors, Add custom connector**, paste `https://<your-project>.vercel.app/mcp`, connect, sign in on the consent page (GitHub, or an emailed link opened in the same browser) and choose **Allow**. Your project's `docs/remote.md` has the same steps for Cursor and Codex.

Every call is recorded in an audit table in your Supabase project, with the name and version of the client that made it. Once people are using the server, `docs/remote.md` ("Which clients connect") has two queries to paste into Supabase's SQL Editor: which clients people use, and which can't show confirmation prompts.

Before the first deploy, install and sign in to two command-line tools, once: `npm install -g vercel` then `vercel login`, and the [Supabase CLI](https://supabase.com/docs/guides/cli) then `supabase login`. Both open a browser. The deploy creates the Supabase project itself. If you belong to several Supabase organizations, it asks which: add `--supabase-org "Org name"` (in quotes) or the slug it lists, and pick a free organization unless you mean to pay for the project. Your project's `docs/remote.md` has the details.

## Updating a project later

```bash
cd my-server
uvx sett-mcp update
```

This pulls in a newer Sett release and keeps your answers and your edits. It needs the project to be a git repository with your changes committed (`git init`, `git add -A`, `git commit -m "start"` the first time), so it can show you what changed.

## Before your project exists: common problems

| You see | Fix |
|---|---|
| `uv` (or `uvx`) is not recognized | Open a new terminal after installing uv. Still missing: run the install command again and read its last lines for where it put `uv`. |
| PowerShell says "running scripts is disabled on this system" | That's the npm launcher for a tool such as `vercel`. Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or type `vercel.cmd` instead of `vercel`. |
| `uvx sett-mcp new` stops with a git error | Install [Git](https://git-scm.com/downloads) (`winget install --id Git.Git -e` on Windows): Sett's template is fetched with it. |
| `sett-mcp update` refuses to run | Commit your changes first (`git add -A`, `git commit -m "before update"`). |

Anything else, or still stuck: ask in [Sett's Discussions](https://github.com/kclarkedesign/sett-mcp/discussions/categories/q-a). Say which OS, client and command, and never paste tokens or keys.
