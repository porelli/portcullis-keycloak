"""Live sign-in smoke run of the extension (contract §8.1), on a realm built
from core's flow tree (src/test/resources/smoke-realm.json).

Keycloak (this image, start-dev, authentication debug log) must be up at
KC_URL with the realm imported and /hub-data mounted from HUB_DATA (this
script writes signin-keycloak.json there). The admin password comes from the
environment (KC_BOOTSTRAP_ADMIN_USERNAME / _PASSWORD), never argv; the test
person's password is random and never printed. KC_LOG is the file the
container's log is copied into (`docker logs`), read to check which
authenticators ran.

With password on: the cold sign-in shows the passkey sign-in, "Try another
way" reaches the password form, the person signs in with a password and
registers a passkey (a CDP virtual authenticator) — the LOGIN Keycloak sends
after that required action carries the history details (pc_kind sign_in,
pc_methods password); pc_method=password shows
the password form at once; a fresh sign-in (prompt=login, max_age=0) with the
password on the fresh-auth-like client smoke-fresh gives pc_fresh=password,
and the SSO session reused there gives no pc_fresh. With password off: the cold sign-in shows the
passkey sign-in without any password choice, a real discoverable assertion
signs in through portcullis-passkey (the ID token's amr has the kind's spk),
and the debug log never shows the password form invoked.

`signin.py x509` is the smoke step "x509 kinds" (contract §8 "The mtls amr
invariant", §8.1 "Flows"): run.sh made a test internal CA (SMOKE_PKI: a
YubiKey CA and a browser CA under one root, their CRLs, one leaf of each for
the person) and started Keycloak with core's x509 options. Each leaf is posted
in Traefik's X-Forwarded-Tls-Client-Cert header (base64 DER, the traefik lookup's form):
the YubiKey leaf signs in with amr mtls and never file, the browser leaf with
file and never mtls; with browser_cert off the browser leaf doesn't sign in,
with yubikey_cert off neither does the YubiKey leaf; a leaf of each kind
revoked in its own CA's CRL never signs in (D30) while the other leaf of that
kind still does, as mtls / file; the LOGIN events carry
the history details (pc_kind, pc_methods, pc_session, pc_ua); and Keycloak
logs no error naming portcullis. The CRLs are served on 0.0.0.0:8200 (the
container reaches the host as vault).

`signin.py impersonation` is the smoke step "impersonation" (contract §8.1
"Impersonation"): the admin API creates the group lldap_admin, root (in it)
and alice; root signs in with a password (pc_method=password); the script
writes impersonation.json (allowed, written now, clients with the smoke
client, a pending record bound to root's Keycloak session id and the same
id's sessions record, ended null) and opens
portcullis-impersonate/start?id= with root's cookies: a 302 to
<auth>/oauth2/start?rd=<PORTCULLIS_PORTAL_URL>. An authorize for smoke then
gives a token for alice with act.sub root, pc_imp.id the id and the amr of
root's session plus hwk (the security_key touch); root's session is gone; a
second start gets 403; a start bound to root's old session from the
impersonated browser gets 403 with the banner; Keycloak's own impersonation
answers an error (--features-disabled=impersonation); the IMPERSONATE event
has pc_imp and pc_act and no reason, the LOGIN as alice pc_act root. The
guard (D42): in the impersonated browser an authorize for smoke-fresh (not in
the file's clients), with pc_method, prompt=login, max_age=0 or acr_values
gets the refused page (403, banner) and nothing is issued, while smoke still
signs in; with the record gone from the file the next authorize gets the
ended page and alice's session is logged out at once. The expiry task: a
second and a third impersonation, each left alone while live (one 15 s run),
then the record ended in the file, the record dropped from a readable file
(only the extension's PORTCULLIS_IMPERSONATED still names alice), or
Keycloak restarted while the file is unreadable (nothing in memory) —
alice's session is logged out by the task within 60 s with no browser
involved. The
log has no error naming portcullis and never the reason.
"""

import base64
import re
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.request


KC = os.environ.get("KC_URL", "http://localhost:18080")
REALM = "portcullis"
CLIENT = "smoke"
# Like the Hub's portcullis-fresh-auth: the portcullis-fresh mapper only.
FRESH_CLIENT = "smoke-fresh"
REDIRECT = "http://localhost:18081/cb"
HUB_DATA = os.environ["HUB_DATA"]
CONTAINER = os.environ.get("KC_CONTAINER", "kc-smoke")

STANDARD = {"op": "any", "items": [
    {"op": "any", "items": ["passkey_synced", "passkey_device", "security_key"]},
    {"op": "any", "items": ["yubikey_cert"]}]}

failures = []
landed = []


class Callback(BaseHTTPRequestHandler):
    """The test client's redirect URI: records where the browser landed."""

    def do_GET(self):
        landed.append("http://localhost:18081" + self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def check(ok, what):
    print(("ok  " if ok else "FAIL ") + what, flush=True)
    if not ok:
        failures.append(what)


def write_config(methods, add_stronger, templates=None):
    doc = {"version": 1, "methods": sorted(methods), "add_stronger": add_stronger,
           "templates": {"standard": STANDARD} if templates is None else templates, "clients": {}, "authenticators": {},
           "mds": {"serial": 1, "next_update": "2026-12-01T00:00:00Z"}}
    path = os.path.join(HUB_DATA, "signin-keycloak.json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def http(method, url, data=None, token=None, form=False):
    headers = {}
    body = None
    if token:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req) as r:
        raw = r.read()
        return json.loads(raw) if raw else None, r.headers


def admin_token():
    tok, _ = http("POST", f"{KC}/realms/master/protocol/openid-connect/token", {
        "grant_type": "password", "client_id": "admin-cli",
        "username": os.environ["KC_BOOTSTRAP_ADMIN_USERNAME"],
        "password": os.environ["KC_BOOTSTRAP_ADMIN_PASSWORD"]}, form=True)
    return tok["access_token"]


def create_person(token, password, required=("webauthn-register-passwordless",), username="alice"):
    base = f"{KC}/admin/realms/{REALM}/users"
    _, headers = http("POST", base, {
        "username": username, "email": f"{username}@example.com", "firstName": username.title(), "lastName": "Smoke",
        "enabled": True, "emailVerified": True,
        "requiredActions": list(required)}, token=token)
    uid = headers["Location"].rsplit("/", 1)[1]
    if password:
        http("PUT", f"{base}/{uid}/reset-password", {"type": "password", "value": password, "temporary": False}, token=token)
    return uid


def authorize_url(client=CLIENT, **extra):
    q = {"client_id": client, "response_type": "code", "scope": "openid",
         "redirect_uri": REDIRECT, "state": secrets.token_hex(8)}
    q.update(extra)
    return f"{KC}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(q)


def log_lines():
    # One stream, in the container's order: slicing by an earlier count
    # (mark) needs stdout and stderr interleaved, not concatenated.
    out = subprocess.run(["docker", "logs", CONTAINER], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return out.stdout.splitlines()


def not_an_error_page(page, what):
    text = page.content()
    check("We are sorry" not in text and "Invalid username or password" not in text
          and page.locator("#kc-error-message").count() == 0, what + ": no error page")


def passkey_page(page, what):
    page.wait_for_load_state("domcontentloaded")
    not_an_error_page(page, what)
    check(page.locator("#authenticateWebAuthnButton").count() == 1, what + ": the passkey sign-in (WebAuthn authenticate) page")


def code_of(url):
    return urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("code", [None])[0]


def id_token_of(code, client=CLIENT):
    tok, _ = http("POST", f"{KC}/realms/{REALM}/protocol/openid-connect/token", {
        "grant_type": "authorization_code", "client_id": client, "code": code, "redirect_uri": REDIRECT}, form=True)
    payload = tok["id_token"].split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def amr_of(code):
    return id_token_of(code).get("amr", [])


def fresh_sign_in_page(page, what):
    """The re-authentication the Hub's popup asks for (prompt=login, max_age=0) on the fresh client."""
    page.goto(authorize_url(FRESH_CLIENT, prompt="login", max_age="0"))
    passkey_page(page, what)


def main():
    from playwright.sync_api import sync_playwright

    password = secrets.token_urlsafe(18)
    token = admin_token()
    uid = create_person(token, password)

    server = HTTPServer(("127.0.0.1", 18081), Callback)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context()
        page = ctx.new_page()
        page.on("dialog", lambda d: d.accept("smoke key"))
        cdp = ctx.new_cdp_session(page)
        cdp.send("WebAuthn.enable", {"enableUI": False})
        auth_id = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
        events = {"added": 0, "asserted": 0}
        cdp.on("WebAuthn.credentialAdded", lambda e: events.__setitem__("added", events["added"] + 1))
        cdp.on("WebAuthn.credentialAsserted", lambda e: events.__setitem__("asserted", events["asserted"] + 1))

        # ── Password on ──
        write_config(["passkey_device", "passkey_synced", "password", "security_key", "yubikey_cert"], True)
        page.goto(authorize_url())
        passkey_page(page, "password on, cold sign-in")
        check(page.locator("#try-another-way").count() == 1, "password on: \"Try another way\" is offered")
        page.locator("#try-another-way").click()
        page.wait_for_load_state("domcontentloaded")
        page.get_by_text("Password", exact=True).first.click()
        page.wait_for_load_state("domcontentloaded")
        check(page.locator("#password").count() == 1, "password on: the password choice reaches the password form")
        page.fill("#username", "alice")
        page.fill("#password", password)
        page.locator("#kc-login").click()
        page.wait_for_load_state("domcontentloaded")
        check(page.locator("#registerWebAuthn").count() == 1, "password on: the passkey registration follows the password sign-in")
        page.locator("#registerWebAuthn").click()
        page.wait_for_url("http://localhost:18081/**", timeout=30000)
        check(events["added"] == 1, "password on: a passkey was registered (virtual authenticator)")
        check(code_of(landed[-1]) is not None, "password on: signed in (authorization code)")
        # That LOGIN is sent after the required action, in the registration's
        # request with its own event builder: portcullis' required action put
        # the sign-in's history details back on it (History.reapply).
        first = [e.get("details", {}) for e in login_events(admin_token(), uid)]
        want = {"pc_kind": "sign_in", "pc_methods": "password", "pc_session": "password"}
        got = {k: first[0].get(k) for k in want} if len(first) == 1 else None
        check(got == want and bool(first[0].get("pc_ua")),
              f"password on: the LOGIN after the passkey registration carries the history details {want} and pc_ua"
              + ("" if got == want else f" (got {first})"))

        fresh = browser.new_context()
        fpage = fresh.new_page()
        fpage.goto(authorize_url(pc_method="password"))
        fpage.wait_for_load_state("domcontentloaded")
        not_an_error_page(fpage, "pc_method=password")
        check(fpage.locator("#password").count() == 1 and fpage.locator("#authenticateWebAuthnButton").count() == 0,
              "pc_method=password: the password form at once")
        fresh.close()

        # The popup's fresh sign-in with a password (contract §8.1 portcullis-fresh):
        # this authentication's password gives pc_fresh=password; the SSO
        # session reused without a sign-in gives none.
        fresh_sign_in_page(page, "fresh sign-in, password on")
        page.locator("#try-another-way").click()
        page.wait_for_load_state("domcontentloaded")
        page.get_by_text("Password", exact=True).first.click()
        page.wait_for_load_state("domcontentloaded")
        check(page.locator("#password").count() == 1, "fresh sign-in: the password form")
        user = page.locator("#username")
        if user.count() == 1 and user.is_editable():
            user.fill("alice")
        page.fill("#password", password)
        before = len(landed)
        page.locator("#kc-login").click()
        page.wait_for_url("http://localhost:18081/**", timeout=30000)
        code = code_of(landed[-1]) if len(landed) > before else None
        check(code is not None, "fresh sign-in: signed in with the password (authorization code)")
        if code:
            claims = id_token_of(code, FRESH_CLIENT)
            check(claims.get("pc_fresh") == "password", f"fresh sign-in with a password: pc_fresh=password (got {claims.get('pc_fresh')!r})")
        before = len(landed)
        page.goto(authorize_url(FRESH_CLIENT))
        page.wait_for_url("http://localhost:18081/**", timeout=30000)
        code = code_of(landed[-1]) if len(landed) > before else None
        check(code is not None, "SSO reuse on the fresh client: a code without a sign-in")
        if code:
            claims = id_token_of(code, FRESH_CLIENT)
            check("pc_fresh" not in claims, f"SSO reuse: no pc_fresh (got {claims.get('pc_fresh')!r})")

        # ── Password off ──
        write_config(["passkey_device", "passkey_synced", "security_key", "yubikey_cert"], False)
        ctx.clear_cookies()
        mark = len(log_lines())
        page.goto(authorize_url())
        passkey_page(page, "password off, cold sign-in")
        check(page.locator("#try-another-way").count() == 0, "password off: no other way offered")
        check(page.locator("#password").count() == 0, "password off: no password field")
        page.locator("#authenticateWebAuthnButton").click()
        page.wait_for_url("http://localhost:18081/**", timeout=30000)
        check(events["asserted"] == 1, "password off: a real discoverable assertion (virtual authenticator)")
        code = code_of(landed[-1])
        check(code is not None, "password off: signed in with the passkey")
        if code:
            amr = amr_of(code)
            check("spk" in amr, f"password off: the ID token's amr has spk (portcullis-passkey + the synced kind's portcullis-method): {amr}")
        ran = [l for l in log_lines()[mark:] if "invoke authenticator.authenticate: portcullis-password-form" in l]
        check(not ran, "password off: the password form was never invoked")
        check(any("invoke authenticator.authenticate: portcullis-passkey" in l for l in log_lines()[mark:]),
              "password off: portcullis-passkey was invoked")
        browser.close()

    cdp_note = "virtual authenticator " + auth_id
    print(f"{len(failures)} failure(s); {cdp_note}")
    sys.exit(1 if failures else 0)


# ── x509 kinds ──

ALL_METHODS = ["browser_cert", "passkey_device", "passkey_synced", "security_key", "yubikey_cert"]
UA = "portcullis-smoke/x509 (kinds)"


class Crl(BaseHTTPRequestHandler):
    """Vault's CRL paths for the two test CAs (the full CRL also as the delta)."""

    files = {}

    def do_GET(self):
        body = self.files.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/pkix-crl")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def leaf_header(path):
    """Traefik's client-cert-pem form, as Keycloak's traefik lookup reads it: the DER in base64, no PEM lines."""
    with open(path) as f:
        return "".join(l.strip() for l in f if l.strip() and not l.startswith("-----"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def cert_sign_in(header):
    """A cold sign-in presenting one leaf: the authorization code, or None when it lands on a page."""
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()), NoRedirect)
    url = authorize_url()
    for _ in range(10):
        req = urllib.request.Request(url, headers={"X-Forwarded-Tls-Client-Cert": header, "User-Agent": UA})
        try:
            with opener.open(req) as r:
                r.read()
                return None  # a page (the passkey sign-in): not signed in
        except urllib.error.HTTPError as e:
            if e.code not in (301, 302, 303, 307):
                return None
            url = urllib.parse.urljoin(url, e.headers["Location"])
        if url.startswith("http://localhost:18081/"):
            return code_of(url)
    return None


def login_events(token, uid):
    events, _ = http("GET", f"{KC}/admin/realms/{REALM}/events?type=LOGIN&user={uid}&max=50", token=token)
    return events or []


def x509_config(methods):
    """signin-keycloak.json with these methods; a pause so a bind mount's cached attributes (Docker Desktop) catch up."""
    write_config(methods, False, {})
    time.sleep(2)


def x509_main():
    pki = os.environ["SMOKE_PKI"]
    for ca in ("int", "file"):
        with open(os.path.join(pki, ca, "crl.der"), "rb") as f:
            der = f.read()
        Crl.files[f"/v1/pki_{ca}/crl"] = der
        Crl.files[f"/v1/pki_{ca}/crl/delta"] = der
    crl = HTTPServer(("0.0.0.0", 8200), Crl)
    threading.Thread(target=crl.serve_forever, daemon=True).start()

    token = admin_token()
    uid = create_person(token, None, required=())
    yubikey = leaf_header(os.path.join(pki, "leaves", "yubikey.pem"))
    browser = leaf_header(os.path.join(pki, "leaves", "browser.pem"))

    x509_config(ALL_METHODS)
    code = cert_sign_in(yubikey)
    check(code is not None, "x509 kinds: the YubiKey leaf signs in")
    if code:
        amr = amr_of(code)
        check("mtls" in amr and "file" not in amr, f"x509 kinds: the YubiKey leaf's amr has mtls, never file: {amr}")
    code = cert_sign_in(browser)
    check(code is not None, "x509 kinds: the browser leaf signs in (browser_cert on)")
    if code:
        amr = amr_of(code)
        check("file" in amr and "mtls" not in amr, f"x509 kinds: the browser leaf's amr has file, never mtls: {amr}")

    token = admin_token()
    details = [e.get("details", {}) for e in login_events(token, uid)]
    for m in ("yubikey_cert", "browser_cert"):
        hit = [d for d in details if d.get("pc_methods") == m]
        check(bool(hit), f"x509 kinds: a LOGIN event with pc_methods={m}" + ("" if hit else f" (got {details})"))
        if hit:
            d = hit[0]
            want = {"pc_kind": "sign_in", "pc_session": m, "pc_ua": UA}
            got = {k: d.get(k) for k in want}
            check(got == want, f"x509 kinds: its history details {want}" + ("" if got == want else f" (got {got})"))

    x509_config([m for m in ALL_METHODS if m != "browser_cert"])
    check(cert_sign_in(browser) is None, "x509 kinds: with browser_cert off the browser leaf doesn't sign in")
    check(cert_sign_in(yubikey) is not None, "x509 kinds: with browser_cert off the YubiKey leaf still signs in")
    x509_config([m for m in ALL_METHODS if m != "yubikey_cert"])
    check(cert_sign_in(yubikey) is None, "x509 kinds: with yubikey_cert off the YubiKey leaf doesn't sign in (never as file)")
    code = cert_sign_in(browser)
    check(code is not None and "mtls" not in amr_of(code), "x509 kinds: with yubikey_cert off the browser leaf still signs in, without mtls")

    # D30: each CA's CRL lists one revoked leaf of its kind (Keycloak's own CRL check, abort if not updated).
    x509_config(ALL_METHODS)
    mark = len(log_lines())
    for kind, amr, other in (("yubikey", "mtls", "file"), ("browser", "file", "mtls")):
        gone = leaf_header(os.path.join(pki, "leaves", f"{kind}-revoked.pem"))
        check(cert_sign_in(gone) is None, f"x509 kinds: the revoked {kind} leaf doesn't sign in")
        code = cert_sign_in(yubikey if kind == "yubikey" else browser)
        got = amr_of(code) if code else None
        check(got is not None and amr in got and other not in got,
              f"x509 kinds: the {kind} leaf that isn't revoked still signs in as {amr}: {got}")
    # Refused by the revocation check itself (Keycloak's X.509 code steps aside without a LOGIN_ERROR).
    why = [l for l in log_lines()[mark:] if "Certificate has been revoked" in l]
    check(len(why) == 2, f"x509 kinds: Keycloak refused both revoked leaves as revoked ({len(why)} log lines)")

    bad = [l for l in log_lines() if "portcullis" in l.lower() and re.search(r"\bERROR\b|Exception", l)]
    check(not bad, "x509 kinds: no error naming portcullis in Keycloak's log" + ("".join("\n    " + l for l in bad[:10])))
    print(f"{len(failures)} failure(s)")
    sys.exit(1 if failures else 0)


# ── Impersonation ──

IMP_REASON = "smoke reason 7f3a"  # must never reach a token, an event or Keycloak's log


def rfc3339(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def claims_of(jwt):
    payload = jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def tokens_of(code, client=CLIENT):
    tok, _ = http("POST", f"{KC}/realms/{REALM}/protocol/openid-connect/token", {
        "grant_type": "authorization_code", "client_id": client, "code": code, "redirect_uri": REDIRECT}, form=True)
    return claims_of(tok["id_token"]), claims_of(tok["access_token"])


def write_impersonation(pending, sessions):
    doc = {"version": 1, "allowed": True, "written": rfc3339(time.time()),
           "clients": ["portcullis-forward-auth", CLIENT], "pending": pending, "sessions": sessions, "notices": {}}
    path = os.path.join(HUB_DATA, "impersonation.json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    time.sleep(2)  # a bind mount's cached attributes (Docker Desktop)


def records(imp_id, sid, created):
    p = {"id": imp_id, "admin": "root", "admin_sid": sid, "target": "alice", "reason": IMP_REASON,
         "fresh": "security_key", "fresh_at": rfc3339(created - 5), "created": rfc3339(created), "until": rfc3339(created + 1800)}
    s = {"id": imp_id, "admin": "root", "target": "alice", "reason": IMP_REASON,
         "started": rfc3339(created), "until": rfc3339(created + 1800), "ended": None}
    return p, s


def open_start(page, url):
    """The browser opens a start URL: the start's own answer (status, Location, body), redirects not followed into."""
    final = page.goto(url)
    req = final.request
    while req.redirected_from is not None:
        req = req.redirected_from
    first = req.response()
    body = first.text() if first.status != 302 else ""
    return first.status, first.headers.get("location", ""), body


def impersonation_main():
    from playwright.sync_api import sync_playwright

    token = admin_token()
    base = f"{KC}/admin/realms/{REALM}"
    _, headers = http("POST", f"{base}/groups", {"name": "lldap_admin"}, token=token)
    gid = headers["Location"].rsplit("/", 1)[1]
    password = secrets.token_urlsafe(18)
    root = create_person(token, password, required=(), username="root")
    http("PUT", f"{base}/users/{root}/groups/{gid}", token=token)
    alice = create_person(token, None, required=())
    write_config(["passkey_device", "passkey_synced", "password", "security_key", "yubikey_cert"], False)
    time.sleep(2)

    server = HTTPServer(("127.0.0.1", 18081), Callback)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    imp_id = secrets.token_hex(16)
    start = f"{KC}/realms/{REALM}/portcullis-impersonate/start?id={imp_id}"

    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context()
        page = ctx.new_page()

        # root signs in with the password.
        page.goto(authorize_url(pc_method="password"))
        page.wait_for_load_state("domcontentloaded")
        check(page.locator("#password").count() == 1, "impersonation: root gets the password form")
        page.fill("#username", "root")
        page.fill("#password", password)
        page.locator("#kc-login").click()
        page.wait_for_url("http://localhost:18081/**", timeout=30000)
        code = code_of(landed[-1])
        check(code is not None, "impersonation: root signed in")
        root_amr = tokens_of(code)[0].get("amr", []) if code else []
        sessions, _ = http("GET", f"{base}/users/{root}/sessions", token=admin_token())
        check(len(sessions or []) == 1, f"impersonation: root has one session ({len(sessions or [])})")
        sid = sessions[0]["id"] if sessions else "none"

        now = int(time.time())
        p1, s1 = records(imp_id, sid, now)
        write_impersonation([p1], [s1])

        status, location, _ = open_start(page, start)
        want = f"{KC}/oauth2/start?rd=" + urllib.parse.quote(os.environ.get("PORTCULLIS_PORTAL_URL", "http://localhost:18081/portal/"), safe="")
        check(status == 302 and location == want, f"impersonation: start answers 302 to oauth2/start (got {status} {location!r})")

        before = len(landed)
        page.goto(authorize_url())
        page.wait_for_url("http://localhost:18081/**", timeout=30000)
        code = code_of(landed[-1]) if len(landed) > before else None
        check(code is not None, "impersonation: the authorize after the start signs in without a form")
        if code:
            idt, access = tokens_of(code)
            for name, c in (("ID token", idt), ("access token", access)):
                check(c.get("preferred_username") == "alice", f"impersonation: {name} preferred_username alice (got {c.get('preferred_username')!r})")
                check(c.get("act") == {"sub": "root"}, f"impersonation: {name} act.sub root (got {c.get('act')!r})")
                check((c.get("pc_imp") or {}).get("id") == imp_id and isinstance((c.get("pc_imp") or {}).get("until"), int),
                      f"impersonation: {name} pc_imp {{id, until}} (got {c.get('pc_imp')!r})")
                check(IMP_REASON not in json.dumps(c), f"impersonation: {name} has no reason")
            amr = idt.get("amr", [])
            check(set(amr) == set(root_amr) | {"hwk"}, f"impersonation: amr = root's {root_amr} + hwk (got {amr})")
        sessions, _ = http("GET", f"{base}/users/{root}/sessions", token=admin_token())
        check(not sessions, f"impersonation: root's session is gone ({sessions})")

        status, _, text = open_start(page, start)
        check(status == 403, f"impersonation: a second start is refused (got {status})")
        check("sign-in-as link can" in text, "impersonation: the refusal page (portcullis-impersonating.ftl)")

        # A start bound to root's old session, opened in the impersonated browser: refused, with the banner.
        id2 = secrets.token_hex(16)
        p2, s2 = records(id2, sid, int(time.time()))
        write_impersonation([p1, p2], [s1, s2])
        status, _, text = open_start(page, f"{KC}/realms/{REALM}/portcullis-impersonate/start?id={id2}")
        check(status == 403 and "You are signed in as alice (by root)" in text and "impersonation/stop" in text,
              f"impersonation: a start from the impersonated browser is refused with the banner and Stop (got {status})")

        # The guard (D42): in the impersonated browser, only the file's clients and the SSO cookie alone.
        for url, what in ((authorize_url(FRESH_CLIENT), "a client not in the file's clients"),
                          (authorize_url(pc_method="security_key"), "pc_method"),
                          (authorize_url(prompt="login"), "prompt=login"),
                          (authorize_url(max_age="0"), "max_age=0"),
                          (authorize_url(acr_values="2"), "acr_values")):
            before = len(landed)
            resp = page.goto(url)
            page.wait_for_load_state("domcontentloaded")
            text = page.content()
            check(len(landed) == before and "Not while you are signed in as alice" in text
                  and "You are signed in as alice (by root)" in text and resp is not None and resp.status == 403,
                  f"impersonation guard: {what} refused with the banner, nothing issued (got {resp.status if resp else None})")
        before = len(landed)
        page.goto(authorize_url())
        page.wait_for_url("http://localhost:18081/**", timeout=30000)
        check(len(landed) > before and code_of(landed[-1]) is not None, "impersonation guard: the listed client still signs in")

        # Ended (the record gone from the file): the next authorize shows the ended page and logs the session out at once.
        write_impersonation([], [])
        before = len(landed)
        page.goto(authorize_url())
        page.wait_for_load_state("domcontentloaded")
        text = page.content()
        check(len(landed) == before and "Your session as alice has ended" in text,
              "impersonation guard: a session no longer live gets the ended page, nothing issued")
        alive, _ = http("GET", f"{base}/users/{alice}/sessions", token=admin_token())
        check(not alive, f"impersonation guard: the ended session is logged out ({alive})")
        browser.close()

        # The expiry task (every 15 s): ended in the file, then an unreadable file (fail closed).
        for how in ("ended", "dropped", "restart"):
            b = p.chromium.launch()
            c = b.new_context()
            pg = c.new_page()
            pg.goto(authorize_url(pc_method="password"))
            pg.wait_for_load_state("domcontentloaded")
            pg.fill("#username", "root")
            pg.fill("#password", password)
            pg.locator("#kc-login").click()
            pg.wait_for_url("http://localhost:18081/**", timeout=30000)
            mine, _ = http("GET", f"{base}/users/{root}/sessions", token=admin_token())
            sid_n = mine[0]["id"] if mine else "none"
            id_n = secrets.token_hex(16)
            pn, sn = records(id_n, sid_n, int(time.time()))
            write_impersonation([pn], [sn])
            status, _, _ = open_start(pg, f"{KC}/realms/{REALM}/portcullis-impersonate/start?id={id_n}")
            check(status == 302, f"impersonation expiry ({how}): started (got {status})")
            alive, _ = http("GET", f"{base}/users/{alice}/sessions", token=admin_token())
            check(len(alive or []) == 1, f"impersonation expiry ({how}): alice's impersonated session exists ({alive})")
            time.sleep(16)  # at least one run of the task with the good file: it stays
            alive, _ = http("GET", f"{base}/users/{alice}/sessions", token=admin_token())
            check(len(alive or []) == 1, f"impersonation expiry ({how}): a live session is left alone ({alive})")
            if how == "ended":
                sn = dict(sn, ended=rfc3339(time.time()))
                write_impersonation([], [sn])
            elif how == "dropped":
                # The record gone from a readable file: only PORTCULLIS_IMPERSONATED still names alice.
                write_impersonation([], [])
            else:
                # Keycloak restarted while the file is unreadable: nothing in memory, the table still names alice.
                subprocess.run(["docker", "stop", CONTAINER], check=True, stdout=subprocess.DEVNULL)
                path = os.path.join(HUB_DATA, "impersonation.json")
                with open(path + ".tmp", "w") as f:
                    f.write("{")
                os.chmod(path + ".tmp", 0o644)
                os.replace(path + ".tmp", path)
                subprocess.run(["docker", "start", CONTAINER], check=True, stdout=subprocess.DEVNULL)
                for _ in range(90):
                    try:
                        http("GET", f"{KC}/realms/{REALM}/.well-known/openid-configuration")
                        break
                    except Exception:
                        time.sleep(2)
            gone_after = None
            t0 = time.time()
            while time.time() - t0 < 60:
                alive, _ = http("GET", f"{base}/users/{alice}/sessions", token=admin_token())
                if not alive:
                    gone_after = time.time() - t0
                    break
                time.sleep(2)
            check(gone_after is not None, f"impersonation expiry ({how}): alice's session logged out by the task"
                  + (f" after {gone_after:.0f} s" if gone_after is not None else " (still there after 60 s)"))
            b.close()

    # Keycloak's own impersonation is off (core's --features-disabled=impersonation).
    try:
        http("POST", f"{base}/users/{alice}/impersonation", {}, token=admin_token())
        check(False, "impersonation: the stock impersonation endpoint is refused (it answered 2xx)")
    except urllib.error.HTTPError as e:
        check(e.code >= 400, f"impersonation: the stock impersonation endpoint is refused ({e.code})")

    token = admin_token()
    events, _ = http("GET", f"{base}/events?type=IMPERSONATE&user={alice}&max=10", token=token)
    events = events or []
    hit = [e for e in events if (e.get("details") or {}).get("pc_imp") == imp_id]
    check(len(hit) == 1 and hit[0]["details"].get("pc_act") == "root",
          f"impersonation: one IMPERSONATE event with pc_imp and pc_act root (got {events})")
    check(IMP_REASON not in json.dumps(events), "impersonation: no reason in the events")
    logins = [e.get("details", {}) for e in login_events(token, alice)]
    check(any(d.get("pc_act") == "root" for d in logins), f"impersonation: the LOGIN as alice has pc_act root (got {logins})")

    lines = log_lines()
    # The expiry phase writes an unreadable file on purpose: its one ERROR (no file values) is expected.
    bad = [l for l in lines if "portcullis" in l.lower() and re.search(r"\bERROR\b|Exception", l)
           and "/hub-data/impersonation.json refused (" not in l]
    check(any("/hub-data/impersonation.json refused (" in l for l in lines), "impersonation: the unreadable file is logged")
    check(not [l for l in lines if "backchannel logout of an impersonated session failed" in l],
          "impersonation: the expiry's backchannel logout worked (no fallback removal)")
    check(not bad, "impersonation: no error naming portcullis in Keycloak's log" + "".join("\n    " + l for l in bad[:10]))
    check(not [l for l in lines if IMP_REASON in l], "impersonation: the reason is never in Keycloak's log")
    print(f"{len(failures)} failure(s)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    if sys.argv[1:] == ["x509"]:
        x509_main()
    elif sys.argv[1:] == ["impersonation"]:
        impersonation_main()
    else:
        main()
