package eu.portcullis.signin;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/** {@code portcullis-method}: see {@link MethodAuthenticator}. */
public final class MethodAuthenticatorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "portcullis-method";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
        AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
            .name(MethodAuthenticator.METHOD)
            .label("Method")
            .helpText("The sign-in method (contract §8.1) this execution stands for; it succeeds only while the method is on.")
            .type(ProviderConfigProperty.LIST_TYPE)
            .options(Methods.IDS)
            .add()
            .build();

    @Override
    public Authenticator create(KeycloakSession session) {
        return new MethodAuthenticator(SigninConfig::current);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Portcullis sign-in method";
    }

    @Override
    public String getHelpText() {
        return "Succeeds only while its sign-in method is switched on (signin-keycloak.json).";
    }

    @Override
    public String getReferenceCategory() {
        return "portcullis-method";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENTS;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return PROPERTIES;
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
