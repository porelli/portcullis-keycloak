package eu.portcullis.signin;

import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.models.KeycloakSession;

/**
 * {@code webauthn-register-passwordless}, overriding Keycloak's own (contract
 * §8.1, plan D5): same id, a higher {@link #order()}, so enroll, the account
 * console and the Hub's "Require passkey" reach {@link PasskeyRegister}.
 */
public final class PasskeyRegisterFactory extends WebAuthnPasswordlessRegisterFactory {
    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return new PasskeyRegister(session);
    }

    @Override
    public String getDisplayText() {
        return "Webauthn Register Passwordless (Portcullis passkey kinds)";
    }

    /** Above the stock factory's 0: Keycloak keeps the highest order of one id. */
    @Override
    public int order() {
        return 1;
    }
}
