"""The consent page Supabase sends people to when an MCP client asks to sign in.

Supabase's OAuth server redirects to `<site_url>/oauth/consent?authorization_id=...`.
This page signs the person in (GitHub, or an emailed link for users you've added),
shows which app is asking and where it will send them back, and records their answer.

Everything it shows comes from Supabase and is written as text, never as HTML: the app
name and return address are chosen by whoever registered the client, so they are
untrusted. The page can't be framed, loads one pinned, integrity-checked script, and
talks only to your Supabase project.
"""

from __future__ import annotations

import json
import secrets
from typing import Any

PATH = "/oauth/consent"

# Pinned with Subresource Integrity, so a changed file on the CDN is refused.
SUPABASE_JS = "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.118.0/dist/umd/supabase.js"
SUPABASE_JS_INTEGRITY = "sha384-TcHRA3zBbn+Lexh5n+Oil4guNPOS3rjNDpGRAN46u/s/mB2IZ50ceC6TYDU2yvgK"


def _js(value: Any) -> str:
    """A JSON literal that is safe inside a <script> element."""
    return json.dumps(value).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render(server_name: str, supabase_url: str, publishable_key: str) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    """The page and its response headers. A fresh nonce on every response."""
    nonce = secrets.token_urlsafe(16)
    csp = "; ".join(
        [
            "default-src 'none'",
            f"script-src 'nonce-{nonce}'",
            f"style-src 'nonce-{nonce}'",
            f"connect-src {supabase_url}",
            "img-src 'self' data:",
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
        ]
    )
    config = _js({"name": server_name, "url": supabase_url, "key": publishable_key})
    body = (
        _PAGE.replace("__NONCE__", nonce)
        .replace("__CONFIG__", config)
        .replace("__SCRIPT__", SUPABASE_JS)
        .replace("__INTEGRITY__", SUPABASE_JS_INTEGRITY)
        .replace("__TITLE__", _html(server_name))
    )
    headers = [
        (b"content-type", b"text/html; charset=utf-8"),
        (b"content-security-policy", csp.encode()),
        (b"x-frame-options", b"DENY"),
        (b"referrer-policy", b"no-referrer"),
        (b"cache-control", b"no-store"),
        (b"x-content-type-options", b"nosniff"),
    ]
    return body.encode(), headers


def _html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Sign in to __TITLE__</title>
<style nonce="__NONCE__">
  :root { --bg: #f6f5f2; --card: #fff; --ink: #1d1d1b; --muted: #6b6a66; --line: #e3e1db; --accent: #1d1d1b; --accent-ink: #fff; --warn: #8a3b12; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #121211; --card: #1c1c1a; --ink: #f1efe9; --muted: #a3a19a; --line: #2e2d2a; --accent: #f1efe9; --accent-ink: #121211; --warn: #f0a070; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px; background: var(--bg); color: var(--ink);
         font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { width: 100%; max-width: 420px; background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 28px; }
  h1 { font-size: 20px; line-height: 1.3; margin: 0 0 8px; }
  p { margin: 0 0 16px; color: var(--muted); }
  strong { color: var(--ink); font-weight: 600; }
  .row { display: flex; gap: 10px; margin-top: 20px; }
  button, input { font: inherit; border-radius: 9px; padding: 10px 14px; }
  button { flex: 1; cursor: pointer; border: 1px solid var(--line); background: transparent; color: var(--ink); }
  button.primary { background: var(--accent); color: var(--accent-ink); border-color: var(--accent); }
  button:disabled { opacity: .5; cursor: default; }
  input { width: 100%; border: 1px solid var(--line); background: transparent; color: var(--ink); margin-top: 8px; }
  .return { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 14px; color: var(--ink); word-break: break-all; }
  .note { font-size: 14px; }
  .error { color: var(--warn); }
  .link { background: none; border: 0; padding: 0; color: var(--muted); text-decoration: underline; cursor: pointer; flex: none; font-size: 14px; }
  hr { border: 0; border-top: 1px solid var(--line); margin: 20px 0; }
  [hidden] { display: none !important; }
</style>
</head>
<body>
<main>
  <section id="loading"><p>Checking your sign-in...</p></section>

  <section id="signin" hidden>
    <h1>Sign in to <span data-name></span></h1>
    <p>An app is asking to use <span data-name></span> for you. Sign in first.</p>
    <div id="github-option" hidden>
      <button class="primary" id="github" type="button">Continue with GitHub</button>
      <hr>
    </div>
    <label class="note" for="email">Get a sign-in link by email (for people already added)</label>
    <input id="email" type="email" autocomplete="email" placeholder="you@example.com">
    <div class="row"><button id="send" type="button">Email me a link</button></div>
    <p class="note" id="sent" hidden>Check your email and open the link in this browser.</p>
  </section>

  <section id="consent" hidden>
    <h1><span id="client"></span> wants to use <span data-name></span></h1>
    <p>Signed in as <strong id="user"></strong>. If you allow it, the app can use this server's tools for you, within your role.</p>
    <p class="note">After you answer, you'll be sent to:<br><span class="return" id="return"></span></p>
    <p class="note">Only allow it if you just started signing in from that app.</p>
    <div class="row">
      <button id="deny" type="button">Deny</button>
      <button class="primary" id="allow" type="button">Allow</button>
    </div>
    <div class="row"><button class="link" id="switch" type="button">Not you? Use another account</button></div>
  </section>

  <section id="message" hidden><p id="text"></p></section>
</main>
<script nonce="__NONCE__" src="__SCRIPT__" integrity="__INTEGRITY__" crossorigin="anonymous"></script>
<script nonce="__NONCE__">
(function () {
  const config = __CONFIG__;
  const $ = (id) => document.getElementById(id);
  document.querySelectorAll("[data-name]").forEach((el) => { el.textContent = config.name; });

  function show(id) {
    ["loading", "signin", "consent", "message"].forEach((s) => { $(s).hidden = s !== id; });
  }
  function fail(text) {
    $("text").textContent = text;
    $("text").className = "error";
    show("message");
  }

  const params = new URLSearchParams(location.search);
  const id = params.get("authorization_id");
  const returnHere = location.origin + location.pathname + (id ? "?authorization_id=" + encodeURIComponent(id) : "");
  if (params.get("error_description") || params.get("error")) {
    return fail("Sign-in didn't finish: " + (params.get("error_description") || params.get("error")));
  }
  if (!id) return fail("This page opens during sign-in from an app such as Claude or Cursor. Start there.");
  if (!window.supabase) return fail("The sign-in script didn't load. Check your connection and reload.");

  const sb = window.supabase.createClient(config.url, config.key, { auth: { flowType: "pkce" } });

  $("github").onclick = async () => {
    const { error } = await sb.auth.signInWithOAuth({ provider: "github", options: { redirectTo: returnHere } });
    if (error) fail("Couldn't start GitHub sign-in: " + error.message);
  };
  // Offer GitHub only once it's set up (the deploy's --github-client-id).
  fetch(config.url + "/auth/v1/settings", { headers: { apikey: config.key } })
    .then((r) => (r.ok ? r.json() : {}))
    .then((s) => { if (s.external && s.external.github) $("github-option").hidden = false; })
    .catch(() => {});
  $("send").onclick = async () => {
    const email = $("email").value.trim();
    if (!email) return;
    $("send").disabled = true;
    const { error } = await sb.auth.signInWithOtp({ email, options: { shouldCreateUser: false, emailRedirectTo: returnHere } });
    $("send").disabled = false;
    if (error) return fail("Couldn't send a link: " + error.message);
    $("sent").hidden = false;
  };
  $("switch").onclick = async () => { await sb.auth.signOut(); show("signin"); };

  async function answer(approve) {
    $("allow").disabled = $("deny").disabled = true;
    const options = { skipBrowserRedirect: true };  // redirect here, whatever the library version does
    const call = approve ? sb.auth.oauth.approveAuthorization(id, options) : sb.auth.oauth.denyAuthorization(id, options);
    const { data, error } = await call;
    if (error || !data || !data.redirect_url) return fail("Couldn't record your answer: " + (error ? error.message : "no address to return to"));
    location.assign(data.redirect_url);  // back to the app, with a code (Allow) or an access_denied error (Deny)
  }
  $("allow").onclick = () => answer(true);
  $("deny").onclick = () => answer(false);

  (async () => {
    const { data: { session } } = await sb.auth.getSession();
    if (!session) return show("signin");
    const { data, error } = await sb.auth.oauth.getAuthorizationDetails(id);
    if (error) return fail("This sign-in request can't be used: " + error.message);
    if (!data.authorization_id) return location.assign(data.redirect_url);  // already allowed before
    $("client").textContent = data.client.name || "An app";
    $("user").textContent = data.user.email || "your account";
    let target = data.redirect_uri;
    try { const u = new URL(data.redirect_uri); target = u.protocol === "https:" || u.protocol === "http:" ? u.host + u.pathname : data.redirect_uri; } catch (e) {}
    $("return").textContent = target;
    show("consent");
  })().catch((e) => fail("Something went wrong: " + e.message));
})();
</script>
</body>
</html>
"""
