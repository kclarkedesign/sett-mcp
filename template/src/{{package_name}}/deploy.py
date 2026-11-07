"""Remote in one command: `deploy vercel --auth supabase`, and `users` to manage who can sign in.

The deploy hosts this server on your own Vercel project and makes a Supabase project its
sign-in. It only uses the Vercel CLI you're logged into and a Supabase personal access
token, and every step can be run again: it checks what is already there first.

    1. Check the Vercel CLI login, the Supabase token and the project's signing keys.
    2. Read the project's publishable and secret keys (creating a secret key if needed).
    3. Link the Vercel project and set its environment variables.
    4. Deploy to production and read the address the server answers at.
    5. Create the audit table and the token hook that adds that address to each token.
    6. Turn on Supabase's OAuth server with this server's consent page; turn off sign-ups.
    7. Check that the server refuses requests without a sign-in, and save the settings.

Supabase's Management API calls used here are documented at
https://supabase.com/docs/reference/api; its OAuth server and SQL endpoint are in beta.
"""

from __future__ import annotations

import getpass
import json
import os
import re
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import consent
from .remote import AUDIT_TABLE_SQL

STATE_FILE = "sett-deploy.json"
API = "https://api.supabase.com"
HOOK = "sett_access_token_hook"
ROLE_KEY = "sett_role"
WRITER = "writer"
USER_AGENT = "sett-deploy"

# (method, url, headers, body) -> (status, body)
Request = Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, bytes]]
# (argv, stdin) -> (returncode, stdout, stderr)
Run = Callable[[list[str], str | None], tuple[int, str, str]]


class DeployError(RuntimeError):
    """A step can't go on. The message says what to do about it."""


def http_request(method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 (fixed https hosts)
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, OSError) as exc:
        raise DeployError(f"Couldn't reach {urlsplit(url).netloc}: {exc}") from exc


def run_command(argv: list[str], stdin: str | None) -> tuple[int, str, str]:
    executable = shutil.which(argv[0])
    if executable is None:
        raise DeployError(f"`{argv[0]}` isn't installed. For Vercel: npm install -g vercel, then vercel login")
    done = subprocess.run(  # noqa: S603 (fixed executable, no shell)
        [executable, *argv[1:]], input=stdin, capture_output=True, text=True, encoding="utf-8", check=False
    )
    return done.returncode, done.stdout, done.stderr


def project_ref(value: str) -> str:
    """Accept a project ref, its https://<ref>.supabase.co URL or a dashboard link."""
    match = re.search(r"(?<![a-z])([a-z]{20})(?![a-z])", value.strip())
    if not match:
        raise DeployError(f"That doesn't look like a Supabase project ref (20 lowercase letters): {value}")
    return match.group(1)


def access_token(env: Mapping[str, str]) -> str:
    token = env.get("SUPABASE_ACCESS_TOKEN", "").strip()
    if not token:
        token = getpass.getpass("Supabase personal access token (supabase.com/dashboard/account/tokens): ").strip()
    if not token:
        raise DeployError("A Supabase personal access token is needed (or set SUPABASE_ACCESS_TOKEN)")
    return token


class Supabase:
    """The few Supabase Management API and Auth admin calls the deploy needs."""

    def __init__(self, token: str, ref: str, request: Request = http_request) -> None:
        self.ref = ref
        self.url = f"https://{ref}.supabase.co"
        self._token = token
        self._request = request

    def _call(self, method: str, url: str, body: Any = None, headers: Mapping[str, str] | None = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        sent = {"Content-Type": "application/json", **(headers or {"Authorization": f"Bearer {self._token}"})}
        status, raw = self._request(method, url, sent, data)
        if status >= 400:
            detail = raw.decode(errors="replace")[:300]
            if status == 401 and url.startswith(API):
                raise DeployError("Supabase didn't accept the access token. Create a new one and try again.")
            raise DeployError(f"Supabase answered {status} to {method} {urlsplit(url).path}: {detail}")
        return json.loads(raw) if raw.strip() else None

    def _api(self, method: str, path: str, body: Any = None) -> Any:
        return self._call(method, f"{API}/v1/projects/{self.ref}{path}", body)

    def project(self) -> dict[str, Any]:
        return self._api("GET", "")

    def api_keys(self) -> list[dict[str, Any]]:
        return self._api("GET", "/api-keys?reveal=true")

    def create_secret_key(self) -> dict[str, Any]:
        return self._api("POST", "/api-keys?reveal=true", {"type": "secret", "name": "sett_server"})

    def sql(self, query: str, parameters: list[Any] | None = None) -> list[dict[str, Any]]:
        body: dict[str, Any] = {"query": query}
        if parameters is not None:
            body["parameters"] = parameters
        return self._api("POST", "/database/query", body) or []

    def auth_config(self) -> dict[str, Any]:
        return self._api("GET", "/config/auth")

    def update_auth(self, changes: dict[str, Any]) -> None:
        self._api("PATCH", "/config/auth", changes)

    def signing_keys(self) -> list[dict[str, Any]]:
        """The project's public token-signing keys. Empty means it still signs with a shared secret."""
        status, raw = self._request("GET", f"{self.url}/auth/v1/.well-known/jwks.json", {}, None)
        if status >= 400:
            raise DeployError(f"Couldn't read {self.url}'s signing keys (HTTP {status})")
        return json.loads(raw).get("keys", [])

    def create_user(self, secret_key: str, email: str, app_metadata: dict[str, Any]) -> bool:
        """Add a confirmed user. False if one with that email already exists."""
        body = json.dumps({"email": email, "email_confirm": True, "app_metadata": app_metadata}).encode()
        headers = {"apikey": secret_key, "Content-Type": "application/json"}
        if secret_key.count(".") == 2:
            # A legacy service_role key is a JWT, and Auth's admin API reads it as a bearer
            # token. The current `sb_secret_...` keys are opaque and go in `apikey` alone.
            headers["Authorization"] = f"Bearer {secret_key}"
        status, raw = self._request("POST", f"{self.url}/auth/v1/admin/users", headers, body)
        if status == 422 and b"exists" in raw:
            return False
        if status >= 400:
            raise DeployError(f"Couldn't add {email}: HTTP {status} {raw.decode(errors='replace')[:200]}")
        return True


class Vercel:
    """The Vercel CLI, run in the project folder."""

    def __init__(self, cwd: Path, scope: str | None = None, run: Run = run_command) -> None:
        self._cwd = cwd
        self._scope = scope
        self._run = run

    def _vercel(self, *args: str, stdin: str | None = None, check: bool = True) -> str:
        argv = ["vercel", *args, "--cwd", str(self._cwd)]
        if self._scope:
            argv += ["--scope", self._scope]
        code, out, err = self._run(argv, stdin)
        if code != 0 and check:
            tail = (err or out).strip().splitlines()[-3:]
            raise DeployError(f"`vercel {args[0]}` failed: " + " / ".join(tail))
        return out

    def whoami(self) -> str:
        try:
            out = self._vercel("whoami").strip()
        except DeployError as exc:
            raise DeployError("The Vercel CLI isn't logged in. Run `vercel login`, then try again.") from exc
        # Run from inside a coding agent, the CLI answers in JSON instead.
        named = re.search(r'"username"\s*:\s*"([^"]+)"', out)
        return named.group(1) if named else (out.splitlines() or ["?"])[-1]

    def link(self, project: str) -> None:
        self._vercel("project", "add", project, check=False)  # already there is fine
        self._vercel("link", "--yes", "--project", project)

    def env_names(self) -> set[str]:
        out = self._vercel("env", "ls", "production", check=False)
        return set(re.findall(r"\b[A-Z][A-Z0-9_]+\b", out))

    def set_env(self, name: str, value: str) -> None:
        self._vercel("env", "add", name, "production", "--force", stdin=value)

    def deploy(self) -> str:
        out = self._vercel("deploy", "--prod", "--yes")
        urls = re.findall(r"https://[^\s]+", out)
        if not urls:
            raise DeployError("Vercel didn't print a deployment URL. Run `vercel deploy --prod` to see why.")
        return urls[-1]

    def aliases(self, deployment: str) -> list[str]:
        out = self._vercel("inspect", deployment, "--json", check=False)
        try:
            data = json.loads(out[out.index("{") :])
        except ValueError:
            return []
        return [a.removeprefix("https://") for a in data.get("aliases", []) if isinstance(a, str)]


def production_host(aliases: list[str], project: str) -> str:
    """The address Vercel gives production: the shortest custom domain, else the shortest vercel.app one."""
    stable = [a for a in aliases if "-git-" not in a]
    custom = sorted((a for a in stable if not a.endswith(".vercel.app")), key=len)
    hosted = sorted((a for a in stable if a.endswith(".vercel.app")), key=len)
    return (custom or hosted or [f"{project}.vercel.app"])[0]


def hook_sql(resource_url: str) -> str:
    """The custom access token hook: adds this server's URL to `aud` on tokens issued to MCP clients.

    Supabase always issues `aud: "authenticated"`. Tokens from its OAuth server carry a
    `client_id` (also after a refresh), so only those are changed; the consent page's own
    website session is left alone, and the server rejects it.
    """
    parts = urlsplit(resource_url)
    if parts.scheme not in ("https", "http") or not re.fullmatch(r"[a-z0-9.:-]+", parts.netloc) or parts.path != "/mcp":
        raise DeployError(f"Unexpected server address: {resource_url}")
    literal = "'" + resource_url.replace("'", "''") + "'"
    return f"""
create or replace function public.{HOOK}(event jsonb)
returns jsonb
language plpgsql
stable
set search_path = ''
as $$
declare
  claims jsonb := event->'claims';
  resource text := {literal};
  aud jsonb;
begin
  if coalesce(claims->>'client_id', '') = '' then
    return event;
  end if;
  aud := case jsonb_typeof(claims->'aud')
    when 'array' then claims->'aud'
    when 'string' then jsonb_build_array(claims->'aud')
    else '[]'::jsonb
  end;
  if not aud @> jsonb_build_array(resource) then
    aud := aud || jsonb_build_array(resource);
  end if;
  return jsonb_build_object('claims', jsonb_set(claims, '{{aud}}', aud));
end
$$;
grant usage on schema public to supabase_auth_admin;
grant execute on function public.{HOOK}(jsonb) to supabase_auth_admin;
revoke execute on function public.{HOOK}(jsonb) from authenticated, anon, public;
""".strip()


def secret_key(supabase: Supabase, keys: list[dict[str, Any]] | None = None) -> str:
    keys = supabase.api_keys() if keys is None else keys
    for key in keys:
        if key.get("type") == "secret" and key.get("api_key"):
            return key["api_key"]
    for key in keys:  # projects from before the new keys
        if key.get("name") == "service_role" and key.get("api_key"):
            return key["api_key"]
    created = supabase.create_secret_key()
    if not created.get("api_key"):
        raise DeployError("Supabase created a secret key but didn't return it; reveal it in the dashboard (Settings, API Keys)")
    return created["api_key"]


def publishable_key(keys: list[dict[str, Any]]) -> str:
    for key in keys:
        if key.get("type") == "publishable" and key.get("api_key"):
            return key["api_key"]
    for key in keys:
        if key.get("name") == "anon" and key.get("api_key"):
            return key["api_key"]
    raise DeployError("The project has no publishable key. Create one in the dashboard (Settings, API Keys).")


def load_state(cwd: Path) -> dict[str, Any]:
    path = cwd / STATE_FILE
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def save_state(cwd: Path, state: dict[str, Any]) -> None:
    # Names and addresses only; secrets stay in Vercel and Supabase.
    (cwd / STATE_FILE).write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


@dataclass
class DeployOptions:
    vercel_project: str
    env_prefix: str
    cwd: Path
    vercel_scope: str | None = None
    enable_writes: bool = False
    github_client_id: str | None = None
    github_secret: str | None = None
    yes: bool = False
    command: str = ""
    say: Callable[[str], None] = print
    sleep: Callable[[float], None] = time.sleep


def deploy(options: DeployOptions, supabase: Supabase, vercel: Vercel, request: Request = http_request) -> str:
    """Run every step and return the server's MCP URL."""
    say, prefix = options.say, options.env_prefix

    say("1/7 Checking your accounts")
    say(f"    Vercel: logged in as {vercel.whoami()}")
    project = supabase.project()
    say(f"    Supabase: project {project.get('name', supabase.ref)} ({supabase.ref})")
    if not supabase.signing_keys():
        raise DeployError(
            "This Supabase project still signs tokens with a shared secret, which a server can't check "
            "safely. In the dashboard open Authentication, then JWT Keys, and choose \"Rotate keys\" to "
            f"switch to ES256: https://supabase.com/dashboard/project/{supabase.ref}/settings/jwt Then run this again."
        )
    auth = supabase.auth_config()

    say("2/7 Reading the project's keys")
    keys = supabase.api_keys()
    publishable = publishable_key(keys)
    secret = secret_key(supabase, keys)

    say(f"3/7 Linking Vercel project {options.vercel_project}")
    vercel.link(options.vercel_project)
    existing = vercel.env_names()
    settings = {
        f"{prefix}_SUPABASE_URL": supabase.url,
        f"{prefix}_SUPABASE_PUBLISHABLE_KEY": publishable,
        f"{prefix}_SUPABASE_SECRET_KEY": secret,
    }
    if f"{prefix}_REQUEST_STATE_KEY" not in existing:
        # Kept across deploys: replacing it would void confirmations in progress.
        settings[f"{prefix}_REQUEST_STATE_KEY"] = secrets.token_urlsafe(48)
    if options.enable_writes:
        settings[f"{prefix}_ENABLE_WRITES"] = "true"
    elif f"{prefix}_ENABLE_WRITES" in existing:
        # Each deploy states the write gate: without --writes it is closed, even if an
        # earlier deploy opened it.
        settings[f"{prefix}_ENABLE_WRITES"] = "false"
    for name, value in settings.items():
        vercel.set_env(name, value)
        say(f"    set {name}")

    say("4/7 Deploying to production (this takes a minute)")
    deployment = vercel.deploy()
    host = production_host(vercel.aliases(deployment), options.vercel_project)
    resource = _resource_url(f"https://{host}", request, options.sleep)
    public = resource.removesuffix("/mcp")
    say(f"    live at {public}")

    site_url = (auth.get("site_url") or "").rstrip("/")
    if site_url not in ("", "http://localhost:3000", public) and not options.yes:
        raise DeployError(
            f"This Supabase project's Site URL is {site_url}. The deploy points it at {public}, which "
            "would break sign-in for anything else using the project. Use a project just for this "
            "server, or run again with --yes to replace it."
        )

    say("5/7 Creating the audit table and the token hook")
    supabase.sql(AUDIT_TABLE_SQL)
    supabase.sql(hook_sql(resource))

    say("6/7 Turning on Supabase's OAuth server")
    changes: dict[str, Any] = {
        "site_url": public,
        "disable_signup": True,
        "oauth_server_enabled": True,
        "oauth_server_allow_dynamic_registration": True,
        "oauth_server_authorization_path": consent.PATH,
        "hook_custom_access_token_enabled": True,
        "hook_custom_access_token_uri": f"pg-functions://postgres/public/{HOOK}",
    }
    if options.github_client_id and options.github_secret:
        changes |= {
            "external_github_enabled": True,
            "external_github_client_id": options.github_client_id,
            "external_github_secret": options.github_secret,
        }
    supabase.update_auth(changes)

    say("7/7 Checking the server")
    _check_server(public, request)
    save_state(
        options.cwd,
        {
            "supabase_project": supabase.ref,
            "vercel_project": options.vercel_project,
            **({"vercel_scope": options.vercel_scope} if options.vercel_scope else {}),
            "url": public,
        },
    )

    github_ready = bool(changes.get("external_github_enabled") or auth.get("external_github_enabled"))
    say("")
    say(f"Done. Connect MCP clients to {resource}")
    say("")
    say("Next:")
    step = 1
    if not github_ready:
        say(f"  {step}. Set up GitHub sign-in (5 minutes): see docs/remote.md, \"GitHub sign-in\"")
        say(f"     Callback URL: {supabase.url}/auth/v1/callback")
        step += 1
    say(f"  {step}. Add the people who may sign in (new sign-ups are off):")
    say(f"       {options.command} users add you@example.com --writer".rstrip())
    if not options.enable_writes:
        say(f"  {step + 1}. Writes are off. To let writers write, run the deploy again with --writes (every deploy without it turns writes off)")
    return resource


def _resource_url(public: str, request: Request, sleep: Callable[[float], None], attempts: int = 10) -> str:
    """Ask the running server which URL it answers for (its protected-resource metadata)."""
    url = f"{public}/.well-known/oauth-protected-resource/mcp"
    status, raw = 0, b""
    for _ in range(attempts):
        status, raw = request("GET", url, {}, None)
        if status == 200:
            resource = json.loads(raw).get("resource", "")
            if not resource.endswith("/mcp"):
                raise DeployError(f"The server reported an unexpected address: {resource}")
            return resource
        sleep(3)
    raise DeployError(
        f"The server at {public} didn't come up (HTTP {status}). Run `vercel logs {urlsplit(public).netloc}` "
        "to see why; a missing setting is reported there."
    )


def _check_server(public: str, request: Request) -> None:
    status, _ = request("POST", f"{public}/mcp", {"Content-Type": "application/json"}, b"{}")
    if status != 401:
        raise DeployError(f"{public}/mcp answered {status} without a sign-in; it should answer 401. Not saving.")
    status, _ = request("GET", f"{public}{consent.PATH}", {}, None)
    if status != 200:
        raise DeployError(f"The consent page at {public}{consent.PATH} answered {status}")


# --- users ------------------------------------------------------------------------------

LIST_USERS = f"""
select email, raw_app_meta_data->>'{ROLE_KEY}' as role, last_sign_in_at
from auth.users order by created_at
""".strip()

SET_ROLE = f"""
update auth.users
set raw_app_meta_data = coalesce(raw_app_meta_data, '{{}}'::jsonb) || jsonb_build_object('{ROLE_KEY}', $2::text)
where lower(email) = lower($1)
returning email
""".strip()

CLEAR_ROLE = f"""
update auth.users
set raw_app_meta_data = coalesce(raw_app_meta_data, '{{}}'::jsonb) - '{ROLE_KEY}'
where lower(email) = lower($1)
returning email
""".strip()


def add_user(supabase: Supabase, email: str, writer: bool, say: Callable[[str], None] = print) -> None:
    created = supabase.create_user(secret_key(supabase), email, {ROLE_KEY: WRITER} if writer else {})
    if created:
        say(f"Added {email}{' as a writer' if writer else ''}. They sign in with GitHub (same email) or an emailed link.")
        return
    say(f"{email} was already added.")
    if writer:
        set_writer(supabase, email, True, say)


def set_writer(supabase: Supabase, email: str, writer: bool, say: Callable[[str], None] = print) -> None:
    rows = supabase.sql(SET_ROLE, [email, WRITER]) if writer else supabase.sql(CLEAR_ROLE, [email])
    if not rows:
        raise DeployError(f"No user with the email {email}. Add them first: users add {email}")
    say(
        f"{email} is now a {'writer' if writer else 'reader'}. It applies when their client next refreshes "
        "its sign-in (within an hour), or right away if they sign in again."
    )


def list_users(supabase: Supabase, say: Callable[[str], None] = print) -> None:
    rows = supabase.sql(LIST_USERS)
    if not rows:
        say("No users yet. Add one: users add you@example.com --writer")
        return
    for row in rows:
        seen = row.get("last_sign_in_at") or "never signed in"
        say(f"{row.get('email')}  {row.get('role') or 'reader'}  {seen}")


def supabase_for(cwd: Path, given: str | None, env: Mapping[str, str] = os.environ) -> Supabase:
    ref = given or load_state(cwd).get("supabase_project")
    if not ref:
        raise DeployError(f"Which Supabase project? Pass --supabase-project, or run the deploy first (it saves {STATE_FILE})")
    return Supabase(access_token(env), project_ref(ref))
