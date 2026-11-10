package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.FlowStatus;

class X509AuthenticatorTest {
    @Test
    void skippedWhenOffOrOtherMethodRequested() {
        Flow off = new Flow();
        new X509Authenticator(false, () -> Configs.of("\"security_key\"", false, "", "")).authenticate(off.context);
        assertEquals(FlowStatus.ATTEMPTED, off.status);

        Flow other = new Flow();
        other.clientNotes.put(PcMethod.CLIENT_NOTE, "passkey");
        new X509Authenticator(false, Configs::plain).authenticate(other.context);
        assertEquals(FlowStatus.ATTEMPTED, other.status);

        Flow deny = new Flow();
        new X509Authenticator(false, () -> SigninConfig.DENY_ALL).action(deny.context);
        assertEquals(AuthenticationFlowError.ACCESS_DENIED, deny.error);
    }

    @Test
    void noCertificateFallsThrough() {
        Flow f = new Flow(); // no X.509 lookup provider, no certificate: the stock "attempted"
        X509Authenticator a = new X509Authenticator(false, Configs::plain);
        a.authenticate(f.context);
        assertEquals(FlowStatus.ATTEMPTED, f.status);
        assertNull(f.authNotes.get(X509Authenticator.METHOD_NOTE));
        assertFalse(a.certificateUser(f.context, f.authenticatorConfig).isPresent());
    }

    @Test
    void confirmationSignsInWithTheNote() {
        Flow f = new Flow();
        f.user = f.person("u-alice", "alice").model; // the stock confirmation page set her
        new X509Authenticator(false, Configs::plain).action(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
        assertEquals("yubikey_cert", f.authNotes.get(X509Authenticator.METHOD_NOTE));
    }
}
