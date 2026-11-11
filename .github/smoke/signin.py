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
registers a passkey (a CDP virtual authenticator); pc_method=password shows
the password form at once. With password off: the cold sign-in shows the
passkey sign-in without any password choice, a real discoverable assertion
signs in through portcullis-passkey (the ID token's amr has the kind's spk),
and the debug log never shows the password form invoked.
"""

import base64
import json
import os
import secrets
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.request

from playwright.sync_api import sync_playwright

KC = os.environ.get("KC_URL", "http://localhost:18080")
REALM = "portcullis"
CLIENT = "smoke"
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


def write_config(methods, add_stronger):
    doc = {"version": 1, "methods": sorted(methods), "add_stronger": add_stronger,
           "templates": {"standard": STANDARD}, "clients": {}, "authenticators": {},
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


def create_person(token, password):
    base = f"{KC}/admin/realms/{REALM}/users"
    _, headers = http("POST", base, {
        "username": "alice", "email": "alice@example.com", "firstName": "Alice", "lastName": "Smoke",
        "enabled": True, "emailVerified": True,
        "requiredActions": ["webauthn-register-passwordless"]}, token=token)
    uid = headers["Location"].rsplit("/", 1)[1]
    http("PUT", f"{base}/{uid}/reset-password", {"type": "password", "value": password, "temporary": False}, token=token)
    return uid


def authorize_url(**extra):
    q = {"client_id": CLIENT, "response_type": "code", "scope": "openid",
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


def amr_of(code):
    tok, _ = http("POST", f"{KC}/realms/{REALM}/protocol/openid-connect/token", {
        "grant_type": "authorization_code", "client_id": CLIENT, "code": code, "redirect_uri": REDIRECT}, form=True)
    payload = tok["id_token"].split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload)).get("amr", [])


def main():
    password = secrets.token_urlsafe(18)
    token = admin_token()
    create_person(token, password)

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

        fresh = browser.new_context()
        fpage = fresh.new_page()
        fpage.goto(authorize_url(pc_method="password"))
        fpage.wait_for_load_state("domcontentloaded")
        not_an_error_page(fpage, "pc_method=password")
        check(fpage.locator("#password").count() == 1 and fpage.locator("#authenticateWebAuthnButton").count() == 0,
              "pc_method=password: the password form at once")
        fresh.close()

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


if __name__ == "__main__":
    main()
