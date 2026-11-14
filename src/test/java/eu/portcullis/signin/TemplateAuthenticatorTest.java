package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.models.Constants;

class TemplateAuthenticatorTest {
    /** The check with a given client-certificate answer for this request. */
    private static TemplateAuthenticator check(SigninConfig cfg, boolean certificate) {
        return new TemplateAuthenticator(() -> cfg) {
            @Override
            protected boolean certificateIsTheirs(AuthenticationFlowContext context, org.keycloak.models.UserModel user, String method) {
                return certificate && "yubikey_cert".equals(method);
            }
        };
    }

    private static Flow signedIn(String... amrs) {
        Flow f = new Flow();
        Flow.Person alice = f.person("u-alice", "alice")
                .passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s"))
                .passkey(PasskeyClassifier.TYPE_SECURITY_KEY, Flow.bytes("k"));
        f.user = alice.model;
        f.completed(amrs);
        return f;
    }

    @Test
    void unlistedClientPasses() {
        Flow f = signedIn("spk");
        f.clientId = "portcullis-forward-auth";
        check(Configs.client(Configs.DEFAULT_METHODS, false, Configs.STRONG), false).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
    }

    @Test
    void listedClientMetPasses() {
        Flow f = signedIn("hwk");
        check(Configs.client(Configs.DEFAULT_METHODS, false, Configs.STRONG), false).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
    }

    @Test
    void listedClientUnmetShowsNeedsStronger() {
        Flow f = new Flow();
        f.user = f.person("u-bob", "bob").passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s")).model;
        f.completed("spk");
        check(Configs.client(Configs.DEFAULT_METHODS, false, Configs.STRONG), false).authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        assertEquals(TemplateAuthenticator.PAGE, f.page);
        NeedsStronger page = (NeedsStronger) f.formAttributes.get(TemplateAuthenticator.ATTRIBUTE);
        assertEquals("Nextcloud", page.getApp());
        assertEquals(List.of("passkey_synced"), page.getSignedIn());
        assertEquals(2, page.getAlternatives().size());
        assertEquals(List.of("security_key"), page.getAlternatives().get(0).getMethods());
        assertTrue(page.getAlternatives().get(0).isNotSetUp());
        assertFalse(page.getAlternatives().get(1).isNotSetUp(), "a certificate is unknown to Keycloak");
        // add_stronger off: a security key is stronger than the synced session → ask your admin;
        // a certificate always → ask your admin.
        assertFalse(page.isSetUpSecurityKey());
        assertTrue(page.isAskAdmin());
        assertEquals("https://auth.example.com/realms/portcullis/account/account-security/signing-in", page.getSigninUrl());

        Flow on = new Flow(); // add_stronger on: the security key gets its set-up link
        on.user = on.person("u-bob", "bob").passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s")).model;
        on.completed("spk");
        check(Configs.client(Configs.DEFAULT_METHODS, true, Configs.STRONG), false).authenticate(on.context);
        assertTrue(((NeedsStronger) on.formAttributes.get(TemplateAuthenticator.ATTRIBUTE)).isSetUpSecurityKey());
    }

    @Test
    void deniesWhenConfigInvalid() {
        for (String client : new String[] {"nextcloud", "portcullis-forward-auth", "account-console"}) {
            Flow f = signedIn("hwk", "mtls");
            f.clientId = client;
            check(SigninConfig.DENY_ALL, true).authenticate(f.context);
            // An error page, nobody signs in, and brute-force protection counts nothing.
            assertEquals(FlowStatus.FORCE_CHALLENGE, f.status, client);
            assertEquals("error", f.page, client);
            assertEquals(List.of(TemplateAuthenticator.UNAVAILABLE), f.formErrors, client);
            assertFalse(f.countedByBruteForce(), client);
        }
    }

    /** What Keycloak's flow reset does before the listener runs: every note and the user gone. */
    private static void reset(Flow f) {
        assertEquals(FlowStatus.FLOW_RESET, f.status);
        assertNotNull(f.resetListener);
        f.authNotes.clear();
        f.userSessionNotes.clear();
        f.user = null;
        f.status = null;
        f.resetListener.run();
    }

    @Test
    void allTemplateMetStepByStep() {
        SigninConfig cfg = Configs.client(Configs.DEFAULT_METHODS, false, Configs.SYNCED_AND_KEY);
        Flow f = signedIn("spk");
        f.authNotes.put(PasskeyAuthenticator.KIND_NOTE, "passkey_synced");
        Object alice = f.user;
        String completed = f.userSessionNotes.get(Constants.AUTHENTICATORS_COMPLETED);
        check(cfg, false).authenticate(f.context);
        reset(f);
        // The flow runs again asking for the security key, as if pc_method named it.
        assertEquals(java.util.Optional.of("security_key"), PcMethod.requested(f.context));
        assertSame(alice, f.user, "the person is kept");
        assertEquals(completed, f.userSessionNotes.get(Constants.AUTHENTICATORS_COMPLETED), "the synced passkey still counts");
        assertEquals("passkey_synced", f.authNotes.get(PasskeyAuthenticator.KIND_NOTE));
        // The re-run signs in with the security key: met.
        f.completed("spk", "hwk");
        check(cfg, false).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
    }

    /** all[password, totp]: the password, then the flow asks for the code, then the LOGIN names both. */
    @Test
    void passwordAndCodeStepByStep() {
        SigninConfig cfg = Configs.client(Configs.WITH_TOTP, false, Configs.PASSWORD_AND_CODE);
        Flow f = new Flow();
        f.user = f.person("u-alice", "alice").otp("otp-1", "phone").model;
        f.completed("pwd");
        f.authNotes.put(PasswordForm.METHOD_NOTE, "password");
        check(cfg, false).authenticate(f.context);
        reset(f);
        assertEquals("totp", f.authNotes.get(PcMethod.STEP_NOTE));
        assertEquals(java.util.Optional.of("totp"), PcMethod.requested(f.context));
        assertEquals("password", f.authNotes.get(PasswordForm.METHOD_NOTE), "the password note is kept");
        // portcullis-otp runs now (the user is known) and signs in with the code.
        f.completed("pwd", "otp");
        f.authNotes.put(OtpAuthenticator.METHOD_NOTE, "totp");
        check(cfg, false).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
        assertEquals("password,totp", f.eventDetails().get(History.METHODS));
        assertEquals("password,totp", f.eventDetails().get(History.SESSION));
        assertEquals("totp", f.clientNotes.get(FreshMapper.NOTE));
    }

    @Test
    void otpNoteKeptAcrossAStep() {
        SigninConfig cfg = Configs.client(Configs.WITH_TOTP, false, Configs.SYNCED_AND_KEY);
        Flow f = new Flow();
        f.user = f.person("u-alice", "alice").passkey(PasskeyClassifier.TYPE_SECURITY_KEY, Flow.bytes("k")).otp("otp-1", "phone").model;
        f.completed("pwd", "otp");
        f.authNotes.put(OtpAuthenticator.METHOD_NOTE, "totp");
        check(cfg, false).authenticate(f.context);
        // spk missing and not set up, hwk missing: no single-missing candidate the person has → the page.
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        Flow g = new Flow();
        g.user = g.person("u-bob", "bob").passkey(PasskeyClassifier.TYPE_SECURITY_KEY, Flow.bytes("k")).otp("otp-1", "phone").model;
        g.completed("spk", "otp");
        g.authNotes.put(OtpAuthenticator.METHOD_NOTE, "totp");
        check(cfg, false).authenticate(g.context);
        reset(g);
        assertEquals("security_key", g.authNotes.get(PcMethod.STEP_NOTE));
        assertEquals("totp", g.authNotes.get(OtpAuthenticator.METHOD_NOTE), "kept over the reset");
    }

    @Test
    void freshOrderTotpAbovePassword() {
        SigninConfig cfg = Configs.of(Configs.WITH_TOTP, false, "", "");
        Flow f = new Flow();
        f.authNotes.put(PasswordForm.METHOD_NOTE, "password");
        f.authNotes.put(OtpAuthenticator.METHOD_NOTE, "totp");
        assertEquals("totp", TemplateAuthenticator.freshMethod(f.authSession, cfg));
        f.authNotes.put(PasskeyAuthenticator.KIND_NOTE, "passkey_synced");
        assertEquals("passkey_synced", TemplateAuthenticator.freshMethod(f.authSession, cfg));
        Flow off = new Flow();
        off.authNotes.put(OtpAuthenticator.METHOD_NOTE, "totp");
        assertEquals("none", TemplateAuthenticator.freshMethod(off.authSession, Configs.of(Configs.WITH_PASSWORD, false, "", "")));
        Flow odd = new Flow();
        odd.authNotes.put(OtpAuthenticator.METHOD_NOTE, "password");
        assertEquals("none", TemplateAuthenticator.freshMethod(odd.authSession, cfg), "the otp note holds totp only");
        assertEquals(Set.of(), TemplateAuthenticator.ranMethods(odd.authSession, cfg));
    }

    @Test
    void totpNotCandidateWithoutCredential() {
        SigninConfig cfg = Configs.client(Configs.WITH_TOTP, false, Configs.PASSWORD_AND_CODE);
        Flow f = new Flow();
        f.user = f.person("u-alice", "alice").passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s")).model;
        f.completed("pwd");
        f.authNotes.put(PasswordForm.METHOD_NOTE, "password");
        check(cfg, false).authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status, "no code to ask for: the page");
        assertEquals(TemplateAuthenticator.PAGE, f.page);
        NeedsStronger page = (NeedsStronger) f.formAttributes.get(TemplateAuthenticator.ATTRIBUTE);
        assertTrue(page.getAlternatives().get(0).isNotSetUp());
        assertFalse(page.isSetUpAuthenticator(), "a password session can't add a code (add_stronger off)");
        assertTrue(page.isAskAdmin());

        // The reserved accounts never get the step, credential or not.
        Flow admin = new Flow();
        admin.user = admin.person("u-admin", "admin").otp("otp-1", "phone").model;
        admin.completed("pwd");
        check(cfg, false).authenticate(admin.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, admin.status);
        // totp off: the template can't name it (the file would be refused), and setUp never lists it.
        assertEquals(Set.of(), TemplateAuthenticator.setUp(admin.user, Configs.of(Configs.WITH_PASSWORD, false, "", "")));
        assertEquals(Set.of("totp"), TemplateAuthenticator.setUp(admin.user, cfg));
    }

    @Test
    void stepFailsWhenTheAccountChanged() {
        SigninConfig cfg = Configs.client(Configs.DEFAULT_METHODS, false, Configs.YUBIKEY_AND_CERT);
        Flow f = signedIn("hwk");
        check(cfg, true).authenticate(f.context);
        reset(f);
        assertEquals("u-alice", f.authNotes.get(TemplateAuthenticator.USER_NOTE));
        // The re-run ends with someone else (their certificate): refused, nobody left set.
        f.user = f.person("u-mallory", "mallory").model;
        f.completed("hwk", "mtls");
        check(cfg, true).authenticate(f.context);
        assertEquals(FlowStatus.FAILED, f.status);
        assertEquals(AuthenticationFlowError.USER_CONFLICT, f.error);
        assertEquals(null, f.user);
    }

    @Test
    void brokerFlowNeverResets() {
        // The setup link's post-broker login: an unmet listed client shows the page, no re-run.
        SigninConfig cfg = Configs.client(Configs.DEFAULT_METHODS, false, Configs.SYNCED_AND_KEY);
        Flow f = signedIn("spk");
        f.authNotes.put(org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "{}");
        check(cfg, false).authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        assertEquals(TemplateAuthenticator.PAGE, f.page);
        assertEquals("none", f.clientNotes.get(FreshMapper.NOTE));

        Flow unlisted = signedIn("inv");
        unlisted.clientId = "portcullis-forward-auth";
        unlisted.authNotes.put(org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "{}");
        check(cfg, false).authenticate(unlisted.context);
        assertEquals(FlowStatus.SUCCESS, unlisted.status);
        assertEquals("none", unlisted.clientNotes.get(FreshMapper.NOTE), "a setup link sets no pc_fresh");
    }

    @Test
    void certificateStepOnlyWhenPresented() {
        SigninConfig cfg = Configs.client(Configs.DEFAULT_METHODS, false, Configs.YUBIKEY_AND_CERT);
        Flow f = signedIn("hwk");
        check(cfg, true).authenticate(f.context);
        reset(f);
        assertEquals(java.util.Optional.of("yubikey_cert"), PcMethod.requested(f.context));

        Flow none = signedIn("hwk");
        check(cfg, false).authenticate(none.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, none.status, "no certificate on this request: it can't be completed here");
    }

    @Test
    void unmeetableShowsThePage() {
        // Both methods of the only alternative missing: no candidate.
        Flow f = signedIn("spk");
        check(Configs.client(Configs.DEFAULT_METHODS, false, Configs.YUBIKEY_AND_CERT), true).authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        assertEquals(TemplateAuthenticator.PAGE, f.page);
    }

    @Test
    void neverAsksTwice() {
        SigninConfig cfg = Configs.client(Configs.DEFAULT_METHODS, false, Configs.SYNCED_AND_KEY);
        Flow f = signedIn("spk");
        f.authNotes.put(TemplateAuthenticator.ASKED_NOTE, "security_key");
        check(cfg, false).authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
    }

    @Test
    void candidatesFollowTheStepUpRule() {
        Rule standard = Configs.client(Configs.DEFAULT_METHODS, false, Configs.STANDARD).templateForClient("nextcloud").orElseThrow();
        // Nothing yet: every alternative lacks one method; only set-up kinds and completable methods.
        assertEquals(List.of("passkey_synced", "security_key"),
                TemplateAuthenticator.candidates(standard, Set.of(), Set.of("passkey_synced", "security_key"), m -> false));
        assertEquals(List.of("passkey_synced", "yubikey_cert"),
                TemplateAuthenticator.candidates(standard, Set.of(), Set.of("passkey_synced"), m -> m.equals("yubikey_cert")));
        Rule both = Configs.client(Configs.DEFAULT_METHODS, false, Configs.YUBIKEY_AND_CERT).templateForClient("nextcloud").orElseThrow();
        assertEquals(List.of(), TemplateAuthenticator.candidates(both, Set.of(), Set.of("security_key"), m -> true));
        assertEquals(List.of("security_key"), TemplateAuthenticator.candidates(both, Set.of("yubikey_cert"), Set.of("security_key"), m -> true));
    }

    @Test
    void passwordCandidateNeverForTheRefusedAccounts() {
        String basicish = "{\"op\": \"all\", \"items\": [\"security_key\", \"password\"]}";
        SigninConfig cfg = Configs.client(Configs.WITH_PASSWORD, false, basicish);
        Flow f = new Flow();
        f.user = f.person("u-admin", "admin").model;
        f.completed("hwk");
        check(cfg, false).authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);

        Flow alice = signedIn("hwk");
        check(cfg, false).authenticate(alice.context);
        reset(alice);
        assertEquals(java.util.Optional.of("password"), PcMethod.requested(alice.context));
    }

    @Test
    void browserCertCompletableWithOwnLeaf() {
        String any = "{\"op\": \"any\", \"items\": [\"browser_cert\"]}";
        SigninConfig cfg = Configs.client(X509AuthenticatorTest.ALL, false, any);
        Flow f = signedIn("hwk");
        new TemplateAuthenticator(() -> cfg) {
            @Override
            protected boolean certificateIsTheirs(AuthenticationFlowContext context, org.keycloak.models.UserModel user, String method) {
                return "browser_cert".equals(method); // her pki_file leaf is presented
            }
        }.authenticate(f.context);
        reset(f);
        assertEquals(java.util.Optional.of("browser_cert"), PcMethod.requested(f.context));

        Flow yubikeyOnly = signedIn("hwk"); // only a YubiKey leaf: no browser_cert step
        check(cfg, true).authenticate(yubikeyOnly.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, yubikeyOnly.status);
    }

    @Test
    void loginEventCarriesHistoryDetails() {
        Flow f = signedIn("hwk");
        f.headers.put("User-Agent", "Mozilla/5.0 (Macintosh) Firefox/140.0");
        f.authNotes.put(PasskeyAuthenticator.KIND_NOTE, "security_key");
        f.event.detail(History.METHOD, "security_key"); // the passkey's pc_method, before its check
        check(Configs.client(Configs.DEFAULT_METHODS, false, Configs.STRONG), false).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
        java.util.Map<String, String> d = f.eventDetails();
        assertEquals("sign_in", d.get(History.KIND));
        assertEquals("security_key", d.get(History.METHODS));
        assertEquals("security_key", d.get(History.SESSION));
        assertEquals("Mozilla/5.0 (Macintosh) Firefox/140.0", d.get(History.UA));
        assertFalse(d.containsKey(History.METHOD), "pc_method names a failure only");
        assertFalse(d.containsKey("pc_act"), "reserved for part 3");

        // An unlisted client gets them too; several methods in the table's order.
        Flow u = signedIn("pwd", "hwk");
        u.clientId = "portcullis-forward-auth";
        u.authNotes.put(PasswordForm.METHOD_NOTE, "password");
        u.authNotes.put(PasskeyAuthenticator.KIND_NOTE, "security_key");
        check(Configs.client(Configs.WITH_PASSWORD, false, Configs.STRONG), false).authenticate(u.context);
        assertEquals(FlowStatus.SUCCESS, u.status);
        assertEquals("password,security_key", u.eventDetails().get(History.METHODS));
        assertEquals("password,security_key", u.eventDetails().get(History.SESSION));
        assertEquals("", u.eventDetails().get(History.UA), "no User-Agent");
    }

    @Test
    void ssoReuseIsSso() {
        Flow f = signedIn("hwk"); // the SSO session's amr, merged by auth-cookie
        f.authNotes.put(CookieAuthenticator.SSO_NOTE, "true");
        check(Configs.client(Configs.DEFAULT_METHODS, false, Configs.STRONG), false).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
        assertEquals("sso", f.eventDetails().get(History.KIND));
        assertEquals("", f.eventDetails().get(History.METHODS));
        assertEquals("security_key", f.eventDetails().get(History.SESSION));
    }

    @Test
    void stepUpKind() {
        Flow f = signedIn("spk", "hwk"); // an SSO session (synced passkey) + a security key now
        f.authNotes.put(CookieAuthenticator.SSO_NOTE, "true");
        f.authNotes.put(PasskeyAuthenticator.KIND_NOTE, "security_key");
        check(Configs.client(Configs.DEFAULT_METHODS, false, Configs.STRONG), false).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
        assertEquals("step_up", f.eventDetails().get(History.KIND));
        assertEquals("security_key", f.eventDetails().get(History.METHODS));
        assertEquals("passkey_synced,security_key", f.eventDetails().get(History.SESSION));
    }

    @Test
    void uaTruncatedAndCleaned() {
        Flow f = signedIn("hwk");
        String ua = "Mozilla/5.0\n" + "x".repeat(150) + "\u0000\t\r" + "y".repeat(150);
        f.headers.put("User-Agent", ua);
        String got = History.ua(f.context);
        assertEquals(256, got.length());
        assertTrue(got.chars().noneMatch(Character::isISOControl), got);
        assertTrue(got.startsWith("Mozilla/5.0xxx"), got);
        assertEquals("", History.clean(null));
        assertEquals("ab", History.clean("a\u007fb\u0085"));
        // A surrogate pair is never cut in half.
        String emoji = "a".repeat(255) + "\uD83D\uDE00";
        assertEquals("a".repeat(255), History.clean(emoji));
    }

    @Test
    void needsStrongerLinksToSigninPage() throws Exception {
        java.util.function.Function<String, String> env =
                k -> TemplateAuthenticator.SIGNIN_URL_ENV.equals(k) ? "https://people.example.com/signin" : null;
        SigninConfig cfg = Configs.client(Configs.DEFAULT_METHODS, true, Configs.STRONG);
        Flow f = new Flow();
        f.user = f.person("u-bob", "bob").passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s")).model;
        f.completed("spk");
        new TemplateAuthenticator(() -> cfg, env).authenticate(f.context);
        NeedsStronger page = (NeedsStronger) f.formAttributes.get(TemplateAuthenticator.ATTRIBUTE);
        assertEquals("https://people.example.com/signin", page.getSigninUrl());
        String html = NeedsStrongerTemplateTest.render(page);
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("href=\"([^\"]*)\"").matcher(html);
        int links = 0;
        while (m.find()) {
            assertEquals("https://people.example.com/signin", m.group(1), html);
            links++;
        }
        assertEquals(2, links, "Set up a security key + Sign-in methods: " + html);

        String account = "https://auth.example.com/realms/portcullis/account/account-security/signing-in";
        for (String bad : new String[] {"javascript:alert(1)", "", "https://", "https://a b"}) {
            assertEquals(account, TemplateAuthenticator.signinPage(f.context, k -> bad), bad);
        }
        assertEquals(account, TemplateAuthenticator.signinPage(f.context, k -> null), "unset: the account console");
        Flow unset = new Flow(); // the public constructor reads the process environment (unset in tests)
        unset.user = unset.person("u-bob", "bob").passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s")).model;
        unset.completed("spk");
        new TemplateAuthenticator(() -> cfg).authenticate(unset.context);
        if (System.getenv(TemplateAuthenticator.SIGNIN_URL_ENV) == null) {
            assertEquals(account, ((NeedsStronger) unset.formAttributes.get(TemplateAuthenticator.ATTRIBUTE)).getSigninUrl());
        }
    }

    // ── Impersonated sessions (D39, D42) ──

    /** The check with alice's impersonated identity cookie and the file. */
    private static TemplateAuthenticator impersonated(SigninConfig cfg, Imp.Ops ops, ImpersonationFile file) {
        return new TemplateAuthenticator(() -> cfg, k -> "https://people.example.com/signin", () -> file, () -> Imp.NOW, ops) {
            @Override
            protected boolean certificateIsTheirs(AuthenticationFlowContext context, org.keycloak.models.UserModel user, String method) {
                return true; // even a certificate that would complete a step: never asked
            }
        };
    }

    /** alice's SSO reuse of her impersonated session (root's methods amrs) for nextcloud. */
    private static Flow aliceSso(Imp.Ops[] ops, String... amrs) {
        Flow f = new Flow();
        Flow.Person alice = f.person("u-alice", "alice").passkey(PasskeyClassifier.TYPE_SECURITY_KEY, Flow.bytes("k"));
        ops[0] = new Imp.Ops(Imp.alice(f, alice, amrs));
        f.user = alice.model;
        f.completed(amrs);
        f.authNotes.put(CookieAuthenticator.SSO_NOTE, "true");
        return f;
    }

    @Test
    void impersonatedNeverAsks() {
        Imp.Ops[] ops = new Imp.Ops[1];
        Flow f = aliceSso(ops, "hwk");
        SigninConfig cfg = Configs.client(Configs.DEFAULT_METHODS, true, "{\"op\": \"all\", \"items\": [\"yubikey_cert\"]}");
        impersonated(cfg, ops[0], ImpersonationGuardTest.LIVE).authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        assertEquals(null, f.resetListener, "no step, no certificate completion");
        assertEquals(ImpersonationResource.PAGE, f.page);
        ImpersonatingPage page = (ImpersonatingPage) f.formAttributes.get(ImpersonationResource.ATTRIBUTE);
        assertEquals(ImpersonatingPage.NEEDS, page.getMode());
        assertEquals("Nextcloud", page.getApp());
        assertEquals(List.of("yubikey_cert"), page.getMethods());
        assertEquals("root", page.getAdmin());
        assertEquals("alice", page.getPerson());
        assertEquals("https://people.example.com/impersonation/stop", page.getStopUrl());
        assertNotNull(f.formAttributes.get(ImpersonationResource.BANNER));
        assertEquals(TemplateAuthenticator.NONE, f.clientNotes.get(FreshMapper.NOTE), "never a fresh sign-in");
    }

    @Test
    void impersonatedPromptLoginRefused() {
        // prompt=login: auth-cookie skipped (no SSO note), root typed a password on top of alice's impersonated cookie.
        Imp.Ops[] ops = new Imp.Ops[1];
        Flow f = aliceSso(ops, "hwk");
        f.authNotes.remove(CookieAuthenticator.SSO_NOTE);
        f.clientNotes.put("prompt", "login");
        f.user = f.person("u-root", "root").model;
        f.authNotes.put(PasswordForm.METHOD_NOTE, "password");
        f.completed("pwd");
        impersonated(Configs.client(Configs.WITH_PASSWORD, false, Configs.STRONG), ops[0], ImpersonationGuardTest.LIVE)
                .authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status, "nothing issued");
        assertEquals(ImpersonatingPage.REFUSED, ((ImpersonatingPage) f.formAttributes.get(ImpersonationResource.ATTRIBUTE)).getMode());
        assertFalse(f.eventDetails().containsKey(History.KIND), "no LOGIN details");
    }

    @Test
    void impersonatedMetSucceedsWithAct() {
        Imp.Ops[] ops = new Imp.Ops[1];
        Flow f = aliceSso(ops, "hwk");
        impersonated(Configs.client(Configs.DEFAULT_METHODS, false, Configs.STRONG), ops[0], ImpersonationGuardTest.LIVE)
                .authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
        assertEquals("sso", f.eventDetails().get(History.KIND));
        assertEquals("root", f.eventDetails().get(History.ACT));
        assertFalse(f.eventDetails().toString().contains(Imp.REASON));

        // An unlisted (gateway) client, listed in the file: success too.
        Flow g = aliceSso(ops, "hwk");
        g.clientId = "portcullis-forward-auth";
        impersonated(Configs.client(Configs.DEFAULT_METHODS, false, Configs.STRONG), ops[0], ImpersonationGuardTest.LIVE)
                .authenticate(g.context);
        assertEquals(FlowStatus.SUCCESS, g.status);
    }

    @Test
    void otherRequiredActionRefused() {
        Imp.Ops[] ops = new Imp.Ops[1];
        Flow f = aliceSso(ops, "hwk");
        f.people().get(0).fake.on("getRequiredActionsStream", a -> java.util.stream.Stream.of("UPDATE_PASSWORD"));
        impersonated(Configs.client(Configs.DEFAULT_METHODS, false, Configs.STRONG), ops[0], ImpersonationGuardTest.LIVE)
                .authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        assertEquals(ImpersonatingPage.REFUSED, ((ImpersonatingPage) f.formAttributes.get(ImpersonationResource.ATTRIBUTE)).getMode());
    }

    @Test
    void impersonatedEndedLoggedOut() {
        Imp.Ops[] ops = new Imp.Ops[1];
        Flow f = aliceSso(ops, "hwk");
        impersonated(Configs.client(Configs.DEFAULT_METHODS, false, Configs.STRONG), ops[0], ImpersonationFile.DENY)
                .authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        ImpersonatingPage ended = (ImpersonatingPage) f.formAttributes.get(ImpersonationResource.ATTRIBUTE);
        assertEquals(ImpersonatingPage.ENDED, ended.getMode());
        assertEquals(f.requestUri.toString(), ended.getSignInAgainUrl());
        assertEquals(null, ended.getStopUrl());
        assertEquals(List.of(f.rootId), ops[0].loggedOut);
    }
}
