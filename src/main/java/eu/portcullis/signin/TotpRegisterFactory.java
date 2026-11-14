package eu.portcullis.signin;

import java.util.Map;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.requiredactions.UpdateTotp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ServerInfoAwareProviderFactory;

/**
 * {@code CONFIGURE_TOTP}, overriding Keycloak's own (contract §8.1
 * "Authenticator-app codes"): in Keycloak 26.8.1 {@link UpdateTotp} is the
 * provider and its factory in one class, so this extends it with the same id
 * and a higher {@link #order()}, and {@link #create} gives a
 * {@link TotpRegister}. Every setup path — the Sign-in page, a setup link,
 * the account console, a hand-made {@code kc_action} URL — runs the
 * override's checks.
 */
public final class TotpRegisterFactory extends UpdateTotp implements ServerInfoAwareProviderFactory {
    /** The server-info marker CI's smoke run checks: the override is the one in use. */
    static final Map<String, String> MARKER = Map.of("portcullis", "totp");

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return new TotpRegister();
    }

    @Override
    public String getDisplayText() {
        return "Configure OTP (Portcullis authenticator apps)";
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
}
