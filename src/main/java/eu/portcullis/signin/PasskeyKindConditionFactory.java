package eu.portcullis.signin;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/** {@code portcullis-condition-passkey-kind}: see {@link PasskeyKindCondition}. */
public final class PasskeyKindConditionFactory implements ConditionalAuthenticatorFactory {
    public static final String PROVIDER_ID = "portcullis-condition-passkey-kind";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
        AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
            .name(PasskeyKindCondition.KIND)
            .label("Passkey kind")
            .helpText("Runs the sub-flow when the passkey that signed in is of this kind.")
            .type(ProviderConfigProperty.LIST_TYPE)
            .options(Methods.PASSKEY_KINDS)
            .add()
            .build();

    @Override
    public ConditionalAuthenticator getSingleton() {
        return PasskeyKindCondition.SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - Portcullis passkey kind";
    }

    @Override
    public String getHelpText() {
        return "Matches when the passkey used in this sign-in is of the configured kind.";
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
