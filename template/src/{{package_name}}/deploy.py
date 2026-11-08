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

import base64
import getpass
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
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
    """Run a CLI, reading what it prints on stdout.

    Its stderr goes straight to your terminal, and so does your keyboard unless a value is
    piped in, so its progress, warnings and any question it asks stay visible and answerable.
    """
    executable = shutil.which(argv[0])
    if executable is None:
        raise DeployError(f"`{argv[0]}` isn't installed. For Vercel: npm install -g vercel, then vercel login")
    done = subprocess.run(  # noqa: S603 (fixed executable, no shell)
        [executable, *argv[1:]], input=stdin, stdout=subprocess.PIPE, text=True, encoding="utf-8", check=False
    )
    return done.returncode, done.stdout, ""


def project_ref(value: str) -> str:
    """Accept a project ref, its https://<ref>.supabase.co URL or a dashboard link."""
    match = re.search(r"(?<![a-z])([a-z]{20})(?![a-z])", value.strip())
    if not match:
        raise DeployError(f"That doesn't look like a Supabase project ref (20 lowercase letters): {value}")
    return match.group(1)


TOKEN_PATTERN = re.compile(r"^sbp_(oauth_|v0_)?[a-f0-9]{40}$")
KEYRING_SERVICE = "Supabase CLI"


def access_token(
    env: Mapping[str, str],
    *,
    ask: Callable[[str], str] = getpass.getpass,
    cli_login: Callable[[Mapping[str, str]], str | None] | None = None,
    say: Callable[[str], None] = lambda message: print(message, file=sys.stderr),
) -> str:
    """A Supabase personal access token: SUPABASE_ACCESS_TOKEN, else `supabase login`'s, else ask."""
    token = env.get("SUPABASE_ACCESS_TOKEN", "").strip()
    if token:
        return token
    token = (cli_login or supabase_cli_token)(env) or ""
    if token:
        say("Using your Supabase CLI login (supabase login).")
        return token
    token = ask("Supabase personal access token (supabase.com/dashboard/account/tokens): ").strip()
    if not token:
        raise DeployError("A Supabase access token is needed: run `supabase login`, set SUPABASE_ACCESS_TOKEN, or paste one")
    return token


def supabase_cli_token(env: Mapping[str, str], run: Callable[..., Any] = subprocess.run) -> str | None:
    """The token `supabase login` saved, read where the Supabase CLI keeps it; None if there isn't one.

    Same order as the CLI: the OS keyring (account = the profile, then the legacy
    "access-token"), then the file it falls back to. Nothing is written or printed.
    """
    home = Path(env.get("SUPABASE_HOME") or Path.home() / ".supabase")
    profile = env.get("SUPABASE_PROFILE", "").strip()
    if not profile:
        try:
            profile = (home / "profile").read_text(encoding="utf-8").strip()
        except OSError:
            profile = ""
    candidates: list[str | None] = []
    if not _is_wsl() and env.get("SUPABASE_NO_KEYRING") != "1":
        for account in (profile or "supabase", "access-token"):
            candidates.append(_keyring_secret(account, run))
    try:
        candidates.append((home / "access-token").read_text(encoding="utf-8"))
    except OSError:
        pass
    for candidate in candidates:
        token = _decode_keyring(candidate or "").strip()
        if TOKEN_PATTERN.match(token):
            return token
    return None


def _is_wsl() -> bool:
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text().lower()
    except OSError:
        return False
    return "microsoft" in release or "wsl" in release


def _decode_keyring(value: str) -> str:
    """Undo the encodings the Go CLI's keyring library used on macOS."""
    value = value.strip()
    try:
        if value.startswith("go-keyring-base64:"):
            return base64.b64decode(value.removeprefix("go-keyring-base64:")).decode()
        if value.startswith("go-keyring-encoded:"):
            return bytes.fromhex(value.removeprefix("go-keyring-encoded:")).decode()
    except ValueError:
        return ""
    return value


def _keyring_secret(account: str, run: Callable[..., Any]) -> str | None:
    if sys.platform == "win32":
        return _windows_credential(f"{KEYRING_SERVICE}:{account}")
    if sys.platform == "darwin":
        argv = ["security", "find-generic-password", "-s", KEYRING_SERVICE, "-a", account, "-w"]
    elif shutil.which("secret-tool"):
        argv = ["secret-tool", "lookup", "service", KEYRING_SERVICE, "username", account]
    else:
        return None
    try:
        done = run(argv, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if getattr(done, "returncode", 1) == 0 else None


def _windows_credential(target: str) -> str | None:
    """Read a generic credential from Windows Credential Manager (where the CLI's keyring writes)."""
    import ctypes
    from ctypes import wintypes

    class Credential(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    try:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return None
    pointer = ctypes.POINTER(Credential)()
    if not advapi.CredReadW(target, 1, 0, ctypes.byref(pointer)):  # 1 = CRED_TYPE_GENERIC
        return None
    try:
        blob = ctypes.string_at(pointer.contents.CredentialBlob, pointer.contents.CredentialBlobSize)
    finally:
        advapi.CredFree(pointer)
    # The CLI stores UTF-8 bytes; tolerate UTF-16 from other writers.
    return blob.decode("utf-16-le") if b"\x00" in blob else blob.decode("utf-8", errors="replace")


class SupabaseAccount:
    """Management API calls that aren't about one project: organizations, new projects, health."""

    def __init__(self, token: str, request: Request = http_request) -> None:
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

    def organizations(self) -> list[dict[str, Any]]:
        return self._call("GET", f"{API}/v1/organizations") or []

    def create_project(self, name: str, organization: str, db_pass: str, region: str) -> dict[str, Any]:
        smart = region in SMART_REGIONS
        body = {
            "name": name,
            "organization_slug": organization,
            "db_pass": db_pass,
            "region_selection": {"type": "smartGroup" if smart else "specific", "code": region},
        }
        return self._call("POST", f"{API}/v1/projects", body)

    def project_status(self, ref: str) -> str:
        return str((self._call("GET", f"{API}/v1/projects/{ref}") or {}).get("status", ""))

    def health(self, ref: str) -> list[dict[str, Any]]:
        return self._call("GET", f"{API}/v1/projects/{ref}/health?services=auth,db,rest") or []

    def for_project(self, ref: str) -> Supabase:
        """A client for one project, with the same token."""
        return Supabase(self._token, ref, self._request)


class Supabase(SupabaseAccount):
    """The few Supabase Management API and Auth admin calls the deploy needs, for one project."""

    def __init__(self, token: str, ref: str, request: Request = http_request) -> None:
        super().__init__(token, request)
        self.ref = ref
        self.url = f"https://{ref}.supabase.co"

    def _api(self, method: str, path: str, body: Any = None) -> Any:
        return self._call(method, f"{API}/v1/projects/{self.ref}{path}", body)

    def project(self) -> dict[str, Any]:
        return self._api("GET", "")

    def api_keys(self) -> list[dict[str, Any]]:
        return self._api("GET", "/api-keys?reveal=true")

    def create_secret_key(self) -> dict[str, Any]:
        body = {"type": "secret", "name": "sett_server", "secret_jwt_template": {"role": "service_role"}}
        return self._api("POST", "/api-keys?reveal=true", body)

    def create_publishable_key(self) -> dict[str, Any]:
        return self._api("POST", "/api-keys?reveal=true", {"type": "publishable", "name": "default"})

    def sql(self, query: str) -> list[dict[str, Any]]:
        """Run fixed SQL (the deploy's own statements; never user input)."""
        return self._api("POST", "/database/query", {"query": query}) or []

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

    def _admin(self, method: str, path: str, secret_key: str, body: Any = None) -> tuple[int, Any]:
        headers = {"apikey": secret_key, "Content-Type": "application/json"}
        if secret_key.count(".") == 2:
            # A legacy service_role key is a JWT, and Auth's admin API reads it as a bearer
            # token. The current `sb_secret_...` keys are opaque and go in `apikey` alone.
            headers["Authorization"] = f"Bearer {secret_key}"
        data = None if body is None else json.dumps(body).encode()
        status, raw = self._request(method, f"{self.url}/auth/v1/admin{path}", headers, data)
        try:
            return status, json.loads(raw) if raw.strip() else None
        except ValueError:
            return status, raw.decode(errors="replace")

    def create_user(self, secret_key: str, email: str, app_metadata: dict[str, Any]) -> bool:
        """Add a confirmed user. False if one with that email already exists."""
        body = {"email": email, "email_confirm": True, "app_metadata": app_metadata}
        status, data = self._admin("POST", "/users", secret_key, body)
        if status == 422 and "exists" in json.dumps(data):
            return False
        if status >= 400:
            raise DeployError(f"Couldn't add {email}: HTTP {status} {str(data)[:200]}")
        return True

    def users(self, secret_key: str) -> list[dict[str, Any]]:
        """Everyone who can sign in, through Auth's admin API (paged)."""
        found: list[dict[str, Any]] = []
        for page in range(1, 1000):
            status, data = self._admin("GET", f"/users?page={page}&per_page=200", secret_key)
            if status >= 400:
                raise DeployError(f"Couldn't list users: HTTP {status} {str(data)[:200]}")
            batch = (data or {}).get("users", [])
            found += batch
            if len(batch) < 200:
                break
        return found

    def update_app_metadata(self, secret_key: str, user_id: str, changes: dict[str, Any]) -> None:
        """Merge keys into a user's app_metadata; a None value removes that key."""
        status, data = self._admin("PUT", f"/users/{user_id}", secret_key, {"app_metadata": changes})
        if status >= 400:
            raise DeployError(f"Couldn't update the user: HTTP {status} {str(data)[:200]}")


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
            detail = " / ".join(tail) if tail else "see its message above"
            raise DeployError(f"`vercel {' '.join(args[:2])}` failed: {detail}")
        return out

    def whoami(self) -> str:
        try:
            out = self._vercel("whoami").strip()
        except DeployError as exc:
            raise DeployError("The Vercel CLI isn't logged in. Run `vercel login`, then try again.") from exc
        # Run from inside a coding agent, the CLI answers in JSON instead.
        named = re.search(r'"username"\s*:\s*"([^"]+)"', out)
        return named.group(1) if named else (out.splitlines() or ["?"])[-1]

    def current_team(self) -> str | None:
        """The team the CLI is using, so `vercel link` needn't ask "Which team?" (it does, even with --yes)."""
        if self._scope:
            return self._scope
        out = self._vercel("teams", "ls", "--format", "json", check=False)
        try:
            teams = json.loads(out[out.index("{") :]).get("teams", [])
        except ValueError:
            return None  # an older CLI: link asks, and the question shows in the terminal
        current = [t.get("slug") for t in teams if t.get("current")] or (
            [teams[0].get("slug")] if len(teams) == 1 else []
        )
        if current and isinstance(current[0], str):
            self._scope = current[0]
        return self._scope

    @property
    def scope(self) -> str | None:
        return self._scope

    def linked_project(self) -> str | None:
        """The project this folder is linked to (`vercel link` writes .vercel/project.json)."""
        try:
            data = json.loads((self._cwd / ".vercel" / "project.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        name = data.get("projectName")
        return name if isinstance(name, str) else None

    def link(self, project: str, *, relink: bool = False) -> None:
        """Link this folder to the project, in the chosen team (--scope) or the CLI's current one.

        An existing link to the same project name is reused, unless `relink` (a team was
        named), since a project of that name may also exist in another team.
        """
        if self.linked_project() == project and not relink:
            return
        self.current_team()
        self._vercel("project", "add", project, check=False)  # already there is fine
        self._vercel("link", "--yes", "--project", project)

    def env_names(self) -> set[str]:
        # Fails loudly: an empty answer from a failed lookup would look like "nothing set
        # yet" and replace the shared key.
        out = self._vercel("env", "ls", "production")
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


def production_hosts(aliases: list[str], project: str) -> list[str]:
    """Where production may answer, most likely first: custom domains, then vercel.app ones.

    The server only answers on its production domain (other hosts get 421), so the deploy
    tries these in order and uses the first that answers.
    """
    stable = [a for a in aliases if "-git-" not in a]
    custom = sorted((a for a in stable if not a.endswith(".vercel.app")), key=len)
    hosted = sorted((a for a in stable if a.endswith(".vercel.app")), key=len)
    return custom + hosted or [f"{project}.vercel.app"]


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
    return ""


SMART_REGIONS = ("americas", "emea", "apac")


def create_supabase_project(
    account: SupabaseAccount,
    name: str,
    *,
    organization: str | None = None,
    region: str = "americas",
    say: Callable[[str], None] = print,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> str:
    """Create a Supabase project for this server and wait until it's ready. Returns its ref."""
    orgs = account.organizations()
    if organization:
        chosen = [o for o in orgs if organization in (o.get("slug"), o.get("name"))]
    else:
        chosen = orgs if len(orgs) == 1 else []
    if not chosen:
        listed = ", ".join(f"{o.get('slug')} ({o.get('name')})" for o in orgs) or "none found"
        if not orgs:
            raise DeployError("Your Supabase account has no organization yet. Create one at supabase.com/dashboard, then run this again.")
        raise DeployError(f"Which Supabase organization? Pass --supabase-org with one of: {listed}")
    slug = str(chosen[0].get("slug"))
    # The database password is only needed to connect to Postgres directly; the server never uses it.
    db_pass = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24))
    say(f"    creating Supabase project {name} in {chosen[0].get('name') or slug} ({region})")
    try:
        ref = str(account.create_project(name, slug, db_pass, region).get("ref") or "")
    except DeployError as exc:
        raise DeployError(
            f"{exc}\nThe free plan allows two active projects across the organizations you own or admin. "
            "Pause or delete one, or pass --supabase-project with an existing project."
        ) from exc
    if not ref:
        raise DeployError("Supabase created the project but didn't return its ref; find it in the dashboard and pass --supabase-project")
    say(f"    project {ref}. Database password (shown once, not saved; only for connecting to Postgres directly): {db_pass}")
    wait_until_ready(account.for_project(ref), say=say, sleep=sleep, clock=clock)
    return ref


def wait_until_ready(
    supabase: Supabase,
    *,
    say: Callable[[str], None] = print,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    limit: float = 15 * 60,
) -> None:
    """Wait for a new project's auth, database and API to be healthy, and its signing keys to appear."""
    deadline, delay, healthy_at = clock() + limit, 3.0, None
    say("    waiting for the project to start (usually a few minutes)")
    while True:
        try:
            if supabase.project_status(supabase.ref) in ("INIT_FAILED", "REMOVED", "GOING_DOWN"):
                raise DeployError(f"Supabase couldn't start project {supabase.ref}; check it in the dashboard")
            services = supabase.health(supabase.ref)
            if services and all(s.get("status") == "ACTIVE_HEALTHY" for s in services):
                healthy_at = healthy_at if healthy_at is not None else clock()
                # Signing keys appear shortly after; if they never do, the deploy's own
                # check explains what to change, so don't wait the full limit for them.
                if supabase.signing_keys() or clock() - healthy_at > 120:
                    return
        except DeployError as exc:
            if "couldn't start" in str(exc):
                raise
        if clock() >= deadline:
            raise DeployError(f"Project {supabase.ref} isn't ready after 15 minutes. Run the deploy again later; it picks up where it stopped.")
        sleep(delay)
        delay = min(delay * 1.5, 30.0)


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
    enable_writes: bool = False
    github_client_id: str | None = None
    github_secret: str | None = None
    yes: bool = False
    command: str = ""
    team_chosen: bool = False  # --scope was given: link in that team even if the folder is linked
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
    # Checked before any key leaves Supabase: a project that already serves another site
    # stays untouched unless you say otherwise.
    site_url = (auth.get("site_url") or "").rstrip("/")
    ours = {"", "http://localhost:3000", load_state(options.cwd).get("url", "")}  # new, or an earlier deploy
    if site_url not in ours and not options.yes:
        raise DeployError(
            f"This Supabase project's Site URL is {site_url}. The deploy would point it at this server, "
            "which breaks sign-in for anything else using the project. Use a project just for this "
            "server, or run again with --yes if that address was this server's."
        )

    say("2/7 Reading the project's keys")
    keys = supabase.api_keys()
    publishable = publishable_key(keys)
    if not publishable:  # a new project may not have one yet
        publishable = supabase.create_publishable_key().get("api_key") or ""
        if not publishable:
            raise DeployError("The project has no publishable key. Create one in the dashboard (Settings, API Keys).")
    secret = secret_key(supabase, keys)

    say(f"3/7 Linking Vercel project {options.vercel_project}")
    vercel.link(options.vercel_project, relink=options.team_chosen)
    if vercel.scope:
        say(f"    team {vercel.scope} (for another, run again with --scope <team>; `vercel teams ls` lists them)")
    existing = vercel.env_names()
    settings = {
        f"{prefix}_SUPABASE_URL": supabase.url,
        f"{prefix}_SUPABASE_PUBLISHABLE_KEY": publishable,
        f"{prefix}_SUPABASE_SECRET_KEY": secret,
    }
    if f"{prefix}_REQUEST_STATE_KEY" not in existing:
        # Kept across deploys: replacing it would void confirmations in progress.
        settings[f"{prefix}_REQUEST_STATE_KEY"] = secrets.token_urlsafe(48)
    # Set on every deploy, so the write gate is always what this run says: on with
    # --writes, off without it, whatever an earlier deploy did.
    settings[f"{prefix}_ENABLE_WRITES"] = "true" if options.enable_writes else "false"
    for name, value in settings.items():
        vercel.set_env(name, value)
        say(f"    set {name}")

    say("4/7 Deploying to production (this takes a minute)")
    deployment = vercel.deploy()
    hosts = production_hosts(vercel.aliases(deployment), options.vercel_project)
    resource = _resource_url([f"https://{h}" for h in hosts], request, options.sleep)
    public = resource.removesuffix("/mcp")
    say(f"    live at {public}")

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
            **({"vercel_scope": vercel.scope} if vercel.scope else {}),
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


def _resource_url(candidates: list[str], request: Request, sleep: Callable[[float], None], attempts: int = 10) -> str:
    """Ask the running server which URL it answers for (its protected-resource metadata)."""
    last = "no answer"
    for _ in range(attempts):
        for public in candidates:
            try:
                status, raw = request("GET", f"{public}/.well-known/oauth-protected-resource/mcp", {}, None)
            except DeployError as exc:  # DNS or TLS not ready yet (a new domain), or a blip
                last = str(exc)
                continue
            last = f"HTTP {status}"
            if status == 200:
                resource = json.loads(raw).get("resource", "")
                if not resource.endswith("/mcp"):
                    raise DeployError(f"The server reported an unexpected address: {resource}")
                return resource
        sleep(3)
    first = candidates[0]
    raise DeployError(
        f"The server at {first} didn't come up (last: {last}). A 404 usually means Vercel didn't run the "
        "app as Python: check that vercel.json (\"framework\": \"python\") and asgi.py are in this folder. "
        f"Otherwise run `vercel logs --deployment {urlsplit(first).netloc}`; a missing setting is reported there."
    )


def _check_server(public: str, request: Request) -> None:
    status, _ = request("POST", f"{public}/mcp", {"Content-Type": "application/json"}, b"{}")
    if status != 401:
        raise DeployError(f"{public}/mcp answered {status} without a sign-in; it should answer 401. Not saving.")
    status, _ = request("GET", f"{public}{consent.PATH}", {}, None)
    if status != 200:
        raise DeployError(f"The consent page at {public}{consent.PATH} answered {status}")


# --- users ------------------------------------------------------------------------------

def add_user(supabase: Supabase, email: str, writer: bool, say: Callable[[str], None] = print) -> None:
    created = supabase.create_user(secret_key(supabase), email, {ROLE_KEY: WRITER} if writer else {})
    if created:
        say(f"Added {email}{' as a writer' if writer else ''}. They sign in with GitHub (same email) or an emailed link.")
        return
    say(f"{email} was already added.")
    if writer:
        set_writer(supabase, email, True, say)


def set_writer(supabase: Supabase, email: str, writer: bool, say: Callable[[str], None] = print) -> None:
    """Give or take the writer role, through Auth's admin API (no SQL, so no quoting to get wrong)."""
    key = secret_key(supabase)
    match = [u for u in supabase.users(key) if (u.get("email") or "").lower() == email.strip().lower()]
    if not match:
        raise DeployError(f"No user with the email {email}. Add them first: users add {email}")
    supabase.update_app_metadata(key, match[0]["id"], {ROLE_KEY: WRITER if writer else None})
    say(
        f"{email} is now a {'writer' if writer else 'reader'}. It applies when their client next refreshes "
        "its sign-in (within an hour), or right away if they sign in again."
    )


def list_users(supabase: Supabase, say: Callable[[str], None] = print) -> None:
    users = supabase.users(secret_key(supabase))
    if not users:
        say("No users yet. Add one: users add you@example.com --writer")
        return
    for user in users:
        role = (user.get("app_metadata") or {}).get(ROLE_KEY) or "reader"
        seen = user.get("last_sign_in_at") or "never signed in"
        say(f"{user.get('email')}  {role}  {seen}")


def supabase_for(cwd: Path, given: str | None, env: Mapping[str, str] = os.environ) -> Supabase:
    ref = given or load_state(cwd).get("supabase_project")
    if not ref:
        raise DeployError(f"Which Supabase project? Pass --supabase-project, or run the deploy first (it saves {STATE_FILE})")
    return Supabase(access_token(env), project_ref(ref))
