"""Remote mode: sign-in, a writer role, a shared confirmation key and an audit table.

All of it is configured by environment variables where the server is deployed, and all
of it stays off unless an authorization server is configured:

    <PREFIX>_SUPABASE_URL          https://<ref>.supabase.co (sets issuer, keys and audit table)
    <PREFIX>_SUPABASE_SECRET_KEY   writes audit rows to the `sett_audit` table
    <PREFIX>_AUTH_ISSUER           any other OAuth 2.1 / OIDC issuer, instead of Supabase
    <PREFIX>_AUTH_JWKS_URL         its public keys (default: <issuer>/.well-known/jwks.json)
    <PREFIX>_PUBLIC_URL            https://your-server.example (default: Vercel's production URL)
    <PREFIX>_REQUEST_STATE_KEY     shared secret so confirmations survive across instances
                                   (comma-separated for rotation: new key first)
    <PREFIX>_ALLOWED_HOSTS         extra Host headers to accept (default: the public URL's host)
    <PREFIX>_WRITER_CLAIM          claim that grants writes (default: app_metadata.sett_role)
    <PREFIX>_WRITER_VALUE          its required value (default: writer)

Writes need both keys: `<PREFIX>_ENABLE_WRITES=true` on the server, and the signed-in
user's writer claim. The claim can only narrow what the server allows, never widen it.
"""

from __future__ import annotations

import json
import logging
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

import anyio.to_thread
import jwt
from mcp.server.auth.provider import AccessToken

log = logging.getLogger(__name__)

# Created by the deploy command; kept here so the server and the deploy agree on it.
AUDIT_TABLE = "sett_audit"
AUDIT_TABLE_SQL = f"""
create table if not exists public.{AUDIT_TABLE} (
  id bigint generated always as identity primary key,
  time timestamptz not null,
  tool text not null,
  kind text not null,
  outcome text not null,
  duration_ms numeric,
  arguments jsonb,
  subject text,
  client_id text
);
alter table public.{AUDIT_TABLE} enable row level security;
""".strip()

ALGORITHMS = ["ES256", "RS256", "EdDSA"]


class RemoteConfigError(ValueError):
    """Remote mode is half-configured: something it needs to run safely is missing."""


class _SigningKeys(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...


@dataclass(frozen=True)
class RemoteSettings:
    public_url: str
    issuer: str
    jwks_url: str
    request_state_keys: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    writer_claim: str = "app_metadata.sett_role"
    writer_value: str = "writer"
    audit_url: str | None = None
    audit_key: str | None = None

    @property
    def resource_url(self) -> str:
        """The URL clients connect to, and the audience every token must carry."""
        return self.public_url.rstrip("/") + "/mcp"

    @property
    def allowed_origins(self) -> tuple[str, ...]:
        """Browser origins to accept: the public URL as written, plus https on extra hosts."""
        public = urlsplit(self.public_url)
        own = f"{public.scheme}://{public.netloc}"
        return (own, *(f"https://{h}" for h in self.allowed_hosts if h != public.netloc))

    @classmethod
    def from_env(cls, prefix: str, env: Mapping[str, str]) -> RemoteSettings | None:
        """Read remote settings, or return None when no authorization server is configured."""

        def get(name: str) -> str:
            return env.get(f"{prefix}_{name}", "").strip()

        supabase = get("SUPABASE_URL").rstrip("/")
        issuer = get("AUTH_ISSUER").rstrip("/") or (f"{supabase}/auth/v1" if supabase else "")
        if not issuer:
            return None

        public_url = get("PUBLIC_URL").rstrip("/")
        if not public_url and env.get("VERCEL_PROJECT_PRODUCTION_URL"):
            public_url = "https://" + env["VERCEL_PROJECT_PRODUCTION_URL"].strip().rstrip("/")
        if not public_url:
            raise RemoteConfigError(f"{prefix}_PUBLIC_URL is required when sign-in is configured")
        if urlsplit(public_url).scheme != "https" and urlsplit(public_url).hostname not in ("localhost", "127.0.0.1"):
            raise RemoteConfigError(f"{prefix}_PUBLIC_URL must use https: {public_url}")

        keys = tuple(k.strip() for k in get("REQUEST_STATE_KEY").split(",") if k.strip())
        if not keys:
            raise RemoteConfigError(
                f"{prefix}_REQUEST_STATE_KEY is required when sign-in is configured: without a shared "
                "key, a confirmation started on one server instance can't finish on another"
            )

        jwks_url = get("AUTH_JWKS_URL") or (
            f"{supabase}/auth/v1/.well-known/jwks.json" if supabase and not get("AUTH_ISSUER") else f"{issuer}/.well-known/jwks.json"
        )
        host = urlsplit(public_url).netloc
        extra_hosts = tuple(h.strip() for h in get("ALLOWED_HOSTS").split(",") if h.strip())
        return cls(
            public_url=public_url,
            issuer=issuer,
            jwks_url=jwks_url,
            request_state_keys=keys,
            allowed_hosts=(host, *extra_hosts),
            writer_claim=get("WRITER_CLAIM") or cls.writer_claim,
            writer_value=get("WRITER_VALUE") or cls.writer_value,
            audit_url=supabase or None,
            audit_key=get("SUPABASE_SECRET_KEY") or None,
        )

    def is_writer(self, token: AccessToken | None) -> bool:
        """True when the signed-in user's writer claim has the required value."""
        if token is None or not token.claims:
            return False
        value: Any = token.claims
        for part in self.writer_claim.split("."):
            value = value.get(part) if isinstance(value, Mapping) else None
        if isinstance(value, list):
            return self.writer_value in value
        return value == self.writer_value


class JWTVerifier:
    """Checks a bearer token against the issuer's public keys (the SDK's `TokenVerifier`).

    A token is accepted only when its signature, issuer and expiry are valid, its audience
    is this server's URL, and it carries a `client_id` (so a sign-in issued to some other
    app, such as a website session, can't be replayed here).
    """

    def __init__(self, settings: RemoteSettings, signing_keys: _SigningKeys | None = None) -> None:
        self._settings = settings
        self._keys = signing_keys or jwt.PyJWKClient(settings.jwks_url, cache_keys=True, lifespan=300)

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            key = await anyio.to_thread.run_sync(self._keys.get_signing_key_from_jwt, token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=ALGORITHMS,
                issuer=self._settings.issuer,
                audience=self._settings.resource_url,
                options={"require": ["exp", "iss", "sub", "aud"]},
            )
        except jwt.PyJWTError as exc:
            log.info("Rejected a bearer token: %s", exc)
            return None
        client_id = claims.get("client_id")
        if not isinstance(client_id, str) or not client_id:
            log.info("Rejected a bearer token without a client_id claim")
            return None
        scope = claims.get("scope", "")
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scope.split() if isinstance(scope, str) else [],
            expires_at=int(claims["exp"]),
            resource=self._settings.resource_url,
            subject=claims["sub"],
            claims=claims,
        )


class StderrAuditSink:
    """One JSON line per call on stderr, which hosting platforms collect as logs."""

    async def write(self, entry: dict[str, Any]) -> None:
        sys.stderr.write("audit " + json.dumps(entry, default=str) + "\n")
        sys.stderr.flush()


class SupabaseAuditSink:
    """Inserts each call into the `sett_audit` table through Supabase's REST API.

    Fails open like the file log: an outage is logged, and the tool call still returns.
    The request is awaited, so on serverless hosts the row is written before the response.
    """

    def __init__(self, base_url: str, secret_key: str, table: str = AUDIT_TABLE, timeout: float = 5.0) -> None:
        self._url = f"{base_url.rstrip('/')}/rest/v1/{table}"
        self._key = secret_key
        self._timeout = timeout

    async def write(self, entry: dict[str, Any]) -> None:
        body = json.dumps(entry, default=str).encode()
        headers = {"apikey": self._key, "Content-Type": "application/json", "Prefer": "return=minimal"}
        # Only the legacy service_role key is a JWT. The current `sb_secret_...` keys are
        # opaque and belong in `apikey` alone: sent as a bearer token they fail as "Invalid JWT".
        if self._key.count(".") == 2:
            headers["Authorization"] = f"Bearer {self._key}"
        request = urllib.request.Request(self._url, data=body, method="POST", headers=headers)

        def send() -> None:
            with urllib.request.urlopen(request, timeout=self._timeout):  # noqa: S310 (https URL from config)
                pass

        try:
            await anyio.to_thread.run_sync(send)
        except (urllib.error.URLError, OSError) as exc:
            log.error("Could not write audit row to %s: %s", self._url, exc)
