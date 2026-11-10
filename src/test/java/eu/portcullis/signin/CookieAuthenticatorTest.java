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
    private static final class Under extends CookieAuthenticator {
        final UserSessionModel sso;
        boolean stockRan;

        Under(SigninConfig cfg, UserSessionModel sso) {
            super(() -> cfg);
            this.sso = sso;
        }

        @Override
        protected AuthenticationManager.AuthResult cookie(AuthenticationFlowContext context) {
            return sso == null ? null : new AuthenticationManager.AuthResult(sso.getUser(), sso, null, null);
        }

        @Override
        protected void stock(AuthenticationFlowContext context) {
            stockRan = true;
            context.attachUserSession(sso);
            context.success();
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
}
