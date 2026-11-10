package eu.portcullis.signin;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.WebAuthnPasswordlessAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;

/** {@code portcullis-passkey}: see {@link PasskeyAuthenticator}. */
public final class PasskeyAuthenticatorFactory extends WebAuthnPasswordlessAuthenticatorFactory {
    public static final String PROVIDER_ID = "portcullis-passkey";

    @Override
    public Authenticator create(KeycloakSession session) {
        return new PasskeyAuthenticator(session, SigninConfig::current);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Portcullis passkey";
    }

    @Override
    public String getHelpText() {
        return "Passwordless WebAuthn accepting the three passkey kinds; records the kind used.";
    }
}
