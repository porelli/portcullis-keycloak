package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationSelectionOption;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;

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
        return option(f, authenticator, null);
    }

    /** An execution of authenticator, with a config holding portcullis.method = method (null: no config). */
    private static AuthenticationSelectionOption option(Flow f, String authenticator, String method) {
        AuthenticationExecutionModel e = new AuthenticationExecutionModel();
        e.setId("exec-" + authenticator + (method == null ? "" : "-" + method));
        e.setAuthenticator(authenticator);
        if (method != null) {
            AuthenticatorConfigModel c = new AuthenticatorConfigModel();
            c.setId("cfg-" + method);
            c.setConfig(new HashMap<>(Map.of(X509Authenticator.METHOD_CONFIG, method)));
            f.configs.put(c.getId(), c);
            e.setAuthenticatorConfig(c.getId());
        }
        return new AuthenticationSelectionOption(f.session, e);
    }

    /** What "Try another way" keeps, by authenticator (an X.509 execution as portcullis-x509:<method>). */
    private static List<String> offered(Flow f, SigninConfig cfg) {
        f.selections = new ArrayList<>(List.of(option(f, PasskeyAuthenticatorFactory.PROVIDER_ID),
                option(f, PasswordFormFactory.PROVIDER_ID), option(f, X509AuthenticatorFactory.PROVIDER_ID, "yubikey_cert"),
                option(f, X509AuthenticatorFactory.PROVIDER_ID, "browser_cert"), option(f, X509AuthenticatorFactory.PROVIDER_ID, "mtls"),
                option(f, X509AuthenticatorFactory.PROVIDER_ID)));
        new PasskeyAuthenticator(f.session, () -> cfg).authenticate(f.context);
        return f.selections.stream().map(o -> {
            AuthenticationExecutionModel e = o.getAuthenticationExecution();
            if (!X509AuthenticatorFactory.PROVIDER_ID.equals(e.getAuthenticator())) {
                return e.getAuthenticator();
            }
            return e.getAuthenticator() + ":" + X509Authenticator.method(f.configs.get(e.getAuthenticatorConfig()));
        }).toList();
    }

    @Test
    void tryAnotherWayOffersOnlyUsableMethods() {
        SigninConfig on = Configs.of(Configs.WITH_PASSWORD, false, "", "");
        assertEquals(List.of("portcullis-passkey", "portcullis-password-form", "portcullis-x509:yubikey_cert"), offered(new Flow(), on));
        assertEquals(List.of("portcullis-passkey", "portcullis-x509:yubikey_cert"), offered(new Flow(), Configs.plain()), "password off");
        Flow step = new Flow();
        step.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key");
        assertEquals(List.of("portcullis-passkey"), offered(step, on), "pc_method asks for a passkey kind");
        Flow admin = new Flow();
        admin.user = admin.person("u-admin", "admin").passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s")).model;
        assertEquals(List.of("portcullis-passkey", "portcullis-x509:yubikey_cert"), offered(admin, on), "admin never gets a password");
    }

    @Test
    void browserExecutionOfferedOnlyWhenBrowserCertOn() {
        SigninConfig on = Configs.of(X509AuthenticatorTest.ALL, false, "", "");
        assertEquals(List.of("portcullis-passkey", "portcullis-x509:yubikey_cert", "portcullis-x509:browser_cert"), offered(new Flow(), on));
        assertEquals(List.of("portcullis-passkey", "portcullis-x509:yubikey_cert"), offered(new Flow(), Configs.plain()), "browser_cert off");
        Flow asked = new Flow();
        asked.clientNotes.put(PcMethod.CLIENT_NOTE, "browser_cert");
        // The passkey's own execution steps aside then, but the list is still trimmed.
        assertEquals(List.of("portcullis-x509:browser_cert"), offered(asked, on).stream().filter(s -> s.startsWith("portcullis-x509")).toList());
        SigninConfig browserOnly = Configs.of("\"browser_cert\", \"passkey_synced\"", false, "", "");
        assertEquals(List.of("portcullis-passkey", "portcullis-x509:browser_cert"), offered(new Flow(), browserOnly), "yubikey_cert off");
    }
}
