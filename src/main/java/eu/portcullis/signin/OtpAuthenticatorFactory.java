package eu.portcullis.signin;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

/** {@code portcullis-otp}: see {@link OtpAuthenticator}. */
public final class OtpAuthenticatorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "portcullis-otp";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
        AuthenticationExecutionModel.Requirement.ALTERNATIVE, AuthenticationExecutionModel.Requirement.DISABLED};

    @Override
    public Authenticator create(KeycloakSession session) {
        return new OtpAuthenticator(SigninConfig::current);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Authenticator app code (Portcullis)";
    }

    @Override
    public String getHelpText() {
        return "A code from an authenticator app, only once the person is known, while the totp method is on; "
                + "never alone, never for admin or portcullis-hub.";
    }

    @Override
    public String getReferenceCategory() {
        return OTPCredentialModel.TYPE;
    }

    /** Configurable: the execution carries its reference value ({@code otp}). */
    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENTS.clone();
    }

    /** Setup runs only through the {@code CONFIGURE_TOTP} override, never from the flow. */
    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
