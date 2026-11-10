package eu.portcullis.signin;

import java.util.List;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

/** {@code portcullis-password-form}: see {@link PasswordForm}. */
public final class PasswordFormFactory extends UsernamePasswordFormFactory {
    public static final String PROVIDER_ID = "portcullis-password-form";

    @Override
    public Authenticator create(KeycloakSession session) {
        return new PasswordForm(SigninConfig::current);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Portcullis password form";
    }

    @Override
    public String getHelpText() {
        return "Username and password, only while the password method is on; never for admin or portcullis-hub.";
    }

    /** Configurable: the execution carries its reference value ({@code pwd}). */
    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}
