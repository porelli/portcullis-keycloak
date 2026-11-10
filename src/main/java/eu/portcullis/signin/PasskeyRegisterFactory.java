package eu.portcullis.signin;

import java.util.Map;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.authentication.requiredactions.WebAuthnRegisterFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ServerInfoAwareProviderFactory;

/**
 * {@code webauthn-register-passwordless}, overriding Keycloak's own (contract
 * §8.1, plan D5): same id, a higher {@link #order()}, so enroll, the account
 * console and the Hub's "Require passkey" reach {@link PasskeyRegister}.
 * {@link TwoFactor} overrides {@code webauthn-register} the same way, so no
 * passkey registration path escapes the classification and the cap.
 */
public final class PasskeyRegisterFactory extends WebAuthnPasswordlessRegisterFactory implements ServerInfoAwareProviderFactory {
    /** The server-info marker CI's smoke run checks: the override is the one in use. */
    static final Map<String, String> MARKER = Map.of("portcullis", "passkey-kinds");

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

    @Override
    public Map<String, String> getOperationalInfo() {
        return MARKER;
    }

    /**
     * {@code webauthn-register} (the stock two-factor registration, which
     * core's realm enables): the same capped, classifying passwordless
     * action. Its credentials are stored under the passkey kinds' types.
     */
    public static final class TwoFactor extends WebAuthnRegisterFactory implements ServerInfoAwareProviderFactory {
        @Override
        public RequiredActionProvider create(KeycloakSession session) {
            return new PasskeyRegister(session);
        }

        @Override
        public String getDisplayText() {
            return "Webauthn Register (Portcullis passkey kinds)";
        }

        @Override
        public int order() {
            return 1;
        }

        @Override
        public Map<String, String> getOperationalInfo() {
            return MARKER;
        }
    }
}
