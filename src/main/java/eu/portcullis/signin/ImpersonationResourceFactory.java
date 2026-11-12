package eu.portcullis.signin;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** {@code portcullis-impersonate}: the realm resource {@link ImpersonationResource} (contract §8.1 "Impersonation"). */
public final class ImpersonationResourceFactory implements RealmResourceProviderFactory {
    public static final String PROVIDER_ID = "portcullis-impersonate";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new ImpersonationResource(session);
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
