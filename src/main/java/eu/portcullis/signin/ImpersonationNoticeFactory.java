package eu.portcullis.signin;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * {@code portcullis-impersonation-notice} (contract §8 "The notice required
 * action", §8.1 "The notice"): registered and enabled by core, added to a
 * person by the Hub at a used impersonation's end.
 */
public final class ImpersonationNoticeFactory implements RequiredActionFactory {
    public static final String PROVIDER_ID = ImpersonationNotice.ID;

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return new ImpersonationNotice();
    }

    @Override
    public String getDisplayText() {
        return "Impersonation notice";
    }

    @Override
    public void init(Config.Scope config) {
        // no configuration
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // nothing to schedule
    }

    @Override
    public void close() {
        // nothing held
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
