package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationSelectionOption;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.models.AuthenticationExecutionModel;

/**
 * Keycloak's AuthenticationSelectionResolver runs the first selectable
 * execution and lists non-credential executions before the credential ones
 * that need no user: portcullis-passkey must not be a CredentialValidator, so
 * the flow's own order (passkey before the password form) decides, and the
 * "Try another way" choices hold only usable methods.
 */
class OfferTest {
    @Test
    void passkeyIsNoCredentialValidator() {
        assertFalse(new PasskeyAuthenticator(null, Configs::plain) instanceof CredentialValidator);
        assertFalse(new PasswordForm(Configs::plain) instanceof CredentialValidator);
    }

    private static AuthenticationSelectionOption option(Flow f, String authenticator) {
        AuthenticationExecutionModel e = new AuthenticationExecutionModel();
        e.setId("exec-" + authenticator);
        e.setAuthenticator(authenticator);
        return new AuthenticationSelectionOption(f.session, e);
    }

    private static List<String> offered(Flow f, SigninConfig cfg) {
        f.selections = new ArrayList<>(List.of(option(f, PasskeyAuthenticatorFactory.PROVIDER_ID),
                option(f, PasswordFormFactory.PROVIDER_ID), option(f, X509AuthenticatorFactory.PROVIDER_ID)));
        new PasskeyAuthenticator(f.session, () -> cfg).authenticate(f.context);
        return f.selections.stream().map(o -> o.getAuthenticationExecution().getAuthenticator()).toList();
    }

    @Test
    void tryAnotherWayOffersOnlyUsableMethods() {
        SigninConfig on = Configs.of(Configs.WITH_PASSWORD, false, "", "");
        assertEquals(List.of("portcullis-passkey", "portcullis-password-form", "portcullis-x509"), offered(new Flow(), on));
        assertEquals(List.of("portcullis-passkey", "portcullis-x509"), offered(new Flow(), Configs.plain()), "password off");
        Flow step = new Flow();
        step.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key");
        assertEquals(List.of("portcullis-passkey"), offered(step, on), "pc_method asks for a passkey kind");
        Flow admin = new Flow();
        admin.user = admin.person("u-admin", "admin").passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s")).model;
        assertEquals(List.of("portcullis-passkey", "portcullis-x509"), offered(admin, on), "admin never gets a password");
    }
}
