package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.models.Constants;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;

class CookieAuthenticatorTest {
    /** The override with the SSO session given and the stock path recorded (it signs in with the cookie). */
    private static class Under extends CookieAuthenticator {
        final UserSessionModel sso;
        boolean stockRan;
        /** What the stock code answers (true: signs in with the cookie; false: attempted, e.g. an acr step-up). */
        boolean stockSignsIn = true;
        final java.util.List<String> loggedOut = new java.util.ArrayList<>();

        Under(SigninConfig cfg, UserSessionModel sso) {
            super(() -> cfg);
            this.sso = sso;
        }

        Under(SigninConfig cfg, UserSessionModel sso, ImpersonationFile file) {
            super(() -> cfg, () -> file, () -> Imp.NOW, k -> "https://people.example.com/signin");
            this.sso = sso;
        }

        final java.util.List<java.net.URI> restarted = new java.util.ArrayList<>();

        @Override
        protected void logOut(AuthenticationFlowContext context, UserSessionModel us) {
            loggedOut.add(us.getId());
        }

        @Override
        protected jakarta.ws.rs.core.Response restart(AuthenticationFlowContext context, java.net.URI to) {
            restarted.add(to);
            return null;
        }

        @Override
        protected AuthenticationManager.AuthResult cookie(AuthenticationFlowContext context) {
            return sso == null ? null : new AuthenticationManager.AuthResult(sso.getUser(), sso, null, null);
        }

        @Override
        protected void stock(AuthenticationFlowContext context) {
            stockRan = true;
            if (!stockSignsIn) {
                context.setUser(sso.getUser());
                context.attempted();
                return;
            }
            context.attachUserSession(sso);
            context.success();
        }
    }

    /**
     * L5: what keeps a code from being the only proof of a re-authentication:
     * under a forced re-authentication the SSO session's executions are never
     * carried over, so portcullis-otp sees no primary method; a step-up (no
     * re-authentication) carries them, and the code may follow.
     */
    @Test
    void reauthenticationCarriesNoExecutionsForTheCode() {
        SigninConfig cfg = Configs.of(Configs.WITH_TOTP, false, "", "");
        for (boolean reauth : new boolean[] {true, false}) {
            Flow f = new Flow();
            Flow.Person alice = f.person("u-alice", "alice").otp("otp-1", "phone");
            f.clientNotes.put(PcMethod.CLIENT_NOTE, "totp");
            UserSessionModel sso = f.userSession(alice, "pwd");
            Under a = new Under(cfg, sso) {
                @Override
                protected boolean reauthenticate(AuthenticationFlowContext context, AuthenticationManager.AuthResult s) {
                    return reauth;
                }
            };
            a.stockSignsIn = false; // Keycloak's re-authentication branch: the user set, attempted
            a.authenticate(f.context);
            assertEquals(FlowStatus.ATTEMPTED, f.status, "reauth=" + reauth);
            String completed = f.userSessionNotes.get(Constants.AUTHENTICATORS_COMPLETED);
            if (reauth) {
                assertTrue(completed == null || !completed.contains("exec-pwd"), "nothing carried over: " + completed);
                assertFalse(OtpAuthenticator.primaryDone(f.context, cfg), "a re-authentication: no primary yet");
                assertEquals(java.util.Optional.empty(), PcMethod.effective(f.context, cfg), "the primary methods first");
            } else {
                assertTrue(completed.contains("exec-pwd"));
                assertTrue(OtpAuthenticator.primaryDone(f.context, cfg), "a step-up: the SSO session's password counts");
                assertEquals(java.util.Optional.of("totp"), PcMethod.effective(f.context, cfg), "only the code");
            }
        }
    }

    @Test
    void attemptsWhenRequestedMethodMissing() {
        Flow f = new Flow();
        Flow.Person alice = f.person("u-alice", "alice");
        f.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key");
        UserSessionModel sso = f.userSession(alice, "spk");
        Under a = new Under(Configs.plain(), sso);
        a.authenticate(f.context);
        assertEquals(FlowStatus.ATTEMPTED, f.status);
        assertSame(alice.model, f.user, "the user is set");
        assertFalse(a.stockRan);
        assertNull(f.attached, "the SSO session alone doesn't sign in");
        // The SSO session's executions are carried over, so the amr accumulates.
        assertTrue(f.userSessionNotes.get(Constants.AUTHENTICATORS_COMPLETED).contains("exec-spk"));
    }

    @Test
    void succeedsWhenRequestedMethodPresent() {
        Flow f = new Flow();
        Flow.Person alice = f.person("u-alice", "alice");
        f.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key");
        Under a = new Under(Configs.plain(), f.userSession(alice, "spk", "hwk"));
        a.authenticate(f.context);
        assertTrue(a.stockRan);
        assertEquals(FlowStatus.SUCCESS, f.status);

        Flow p = new Flow(); // pc_method=passkey: any passkey kind will do
        Flow.Person bob = p.person("u-bob", "bob");
        p.clientNotes.put(PcMethod.CLIENT_NOTE, "passkey");
        Under b = new Under(Configs.plain(), p.userSession(bob, "dpk"));
        b.authenticate(p.context);
        assertTrue(b.stockRan);
    }

    @Test
    void stockWithoutPcMethodOrCookie() {
        Flow f = new Flow();
        Flow.Person alice = f.person("u-alice", "alice");
        Under a = new Under(Configs.plain(), f.userSession(alice, "spk"));
        a.authenticate(f.context);
        assertTrue(a.stockRan, "no pc_method: the stock cookie check");

        Flow n = new Flow();
        n.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key");
        Under none = new Under(Configs.plain(), null);
        none.authenticate(n.context);
        assertEquals(FlowStatus.ATTEMPTED, n.status);
        assertNull(n.user);
    }

    @Test
    void switchedOffMethodIsMissing() {
        Flow f = new Flow();
        Flow.Person alice = f.person("u-alice", "alice");
        f.clientNotes.put(PcMethod.CLIENT_NOTE, "passkey");
        // The session's synced passkey counts as nothing while passkey_synced is off.
        SigninConfig cfg = Configs.of("\"security_key\", \"yubikey_cert\"", false, "", "");
        Under a = new Under(cfg, f.userSession(alice, "spk"));
        a.authenticate(f.context);
        assertEquals(FlowStatus.ATTEMPTED, f.status);
        assertFalse(a.stockRan);
    }

    // ── Impersonated identity cookies (D42) ──

    @Test
    void impersonatedOnlyListedClients() {
        Flow ok = new Flow();
        ok.clientId = "portcullis-forward-auth";
        Under a = new Under(Configs.plain(), Imp.alice(ok, ok.person("u-alice", "alice"), "hwk"), ImpersonationGuardTest.LIVE);
        a.authenticate(ok.context);
        assertTrue(a.stockRan, "a listed client: the stock SSO reuse");
        assertEquals(FlowStatus.SUCCESS, ok.status);
        assertEquals("true", ok.authNotes.get(CookieAuthenticator.SSO_NOTE));

        for (String client : java.util.List.of("portcullis-ai-x", "portcullis-fresh-auth", "account-console")) {
            Flow f = new Flow();
            f.clientId = client;
            Under b = new Under(Configs.plain(), Imp.alice(f, f.person("u-alice", "alice"), "hwk"), ImpersonationGuardTest.LIVE);
            b.authenticate(f.context);
            assertFalse(b.stockRan, client);
            assertEquals(FlowStatus.FORCE_CHALLENGE, f.status, client);
            assertEquals(ImpersonationResource.PAGE, f.page, client);
            assertEquals(ImpersonatingPage.REFUSED, ((ImpersonatingPage) f.formAttributes.get(ImpersonationResource.ATTRIBUTE)).getMode());
            assertNull(f.attached, client);
            assertTrue(b.loggedOut.isEmpty(), client);
        }
    }

    @Test
    void impersonatedPcMethodRefused() {
        Flow f = new Flow();
        f.clientId = "portcullis-forward-auth";
        f.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key");
        Under a = new Under(Configs.plain(), Imp.alice(f, f.person("u-alice", "alice"), "spk"), ImpersonationGuardTest.LIVE);
        a.authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        assertEquals(ImpersonatingPage.REFUSED, ((ImpersonatingPage) f.formAttributes.get(ImpersonationResource.ATTRIBUTE)).getMode());
        assertNull(f.user, "never handed to the sign-in flow");
        assertFalse(a.stockRan);
        assertNull(f.userSessionNotes.get(Constants.AUTHENTICATORS_COMPLETED), "nothing carried over");
    }

    @Test
    void impersonatedReauthenticationRefused() {
        for (String[] note : new String[][] {{"prompt", "login"}, {"max_age", "0"},
                {Constants.REQUESTED_LEVEL_OF_AUTHENTICATION, "2"}}) {
            Flow f = new Flow();
            f.clientId = "portcullis-forward-auth";
            f.clientNotes.put(note[0], note[1]);
            Under a = new Under(Configs.plain(), Imp.alice(f, f.person("u-alice", "alice"), "hwk"), ImpersonationGuardTest.LIVE);
            a.authenticate(f.context);
            assertEquals(FlowStatus.FORCE_CHALLENGE, f.status, note[0]);
            assertFalse(a.stockRan, note[0]);
        }
        // The stock code not signing in with the cookie (an acr step-up, a forked flow …): refused, never a sign-in.
        Flow f = new Flow();
        f.clientId = "portcullis-forward-auth";
        Under a = new Under(Configs.plain(), Imp.alice(f, f.person("u-alice", "alice"), "hwk"), ImpersonationGuardTest.LIVE);
        a.stockSignsIn = false;
        a.authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        assertEquals(ImpersonationResource.PAGE, f.page);
    }

    @Test
    void endedSessionLoggedOut() {
        Flow f = new Flow();
        f.clientId = "portcullis-forward-auth";
        UserSessionModel us = Imp.alice(f, f.person("u-alice", "alice"), "hwk");
        Under a = new Under(Configs.plain(), us, Imp.file(Imp.ID, "alice", "\"" + Imp.NOW.minusSeconds(3) + "\"", "portcullis-forward-auth"));
        a.authenticate(f.context);
        assertEquals(java.util.List.of(us.getId()), a.loggedOut);
        // After Stop: the same authorize again without the session — the normal sign-in page, never the ended page.
        assertEquals(java.util.List.of(f.requestUri), a.restarted);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        assertNull(f.page);
        assertFalse(a.stockRan);
        assertNull(f.user, "never a sign-in as the person");
    }
}
