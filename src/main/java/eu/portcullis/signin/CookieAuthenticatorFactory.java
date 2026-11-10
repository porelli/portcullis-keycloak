package eu.portcullis.signin;

import java.util.Map;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ServerInfoAwareProviderFactory;

/**
 * {@code auth-cookie}, overriding Keycloak's own (contract §8.1): same id, a
 * higher {@link #order()} (Keycloak keeps the highest order of one id), and
 * the server-info marker CI's smoke run checks.
 */
public final class CookieAuthenticatorFactory extends org.keycloak.authentication.authenticators.browser.CookieAuthenticatorFactory
        implements ServerInfoAwareProviderFactory {
    static final Map<String, String> MARKER = Map.of("portcullis", "pc-method");

    @Override
    public Authenticator create(KeycloakSession session) {
        return new CookieAuthenticator(SigninConfig::current);
    }

    @Override
    public String getDisplayType() {
        return "Cookie (Portcullis pc_method)";
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
