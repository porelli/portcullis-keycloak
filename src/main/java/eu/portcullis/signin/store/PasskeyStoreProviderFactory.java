package eu.portcullis.signin.store;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;

/**
 * {@code portcullis-passkey-store} (plan D5): the extension's JPA entities and
 * the Liquibase changelog that creates {@code PORTCULLIS_PASSKEY},
 * {@code PORTCULLIS_SIGNIN_STATE} and {@code PORTCULLIS_IMPERSONATED}.
 */
public final class PasskeyStoreProviderFactory implements JpaEntityProviderFactory {
    public static final String PROVIDER_ID = "portcullis-passkey-store";
    public static final String CHANGELOG = "META-INF/portcullis-passkey-changelog.xml";

    @SuppressWarnings("removal")
    private static final class Provider implements JpaEntityProvider {
        @Override
        public List<Class<?>> getEntities() {
            return List.of(PasskeyEntity.class, SigninStateEntity.class, ImpersonatedEntity.class);
        }

        @Override
        public String getChangelogLocation() {
            return CHANGELOG;
        }

        @Override
        public String getFactoryId() {
            return PROVIDER_ID;
        }

        @Override
        public void close() {
            // nothing held
        }
    }

    @Override
    public JpaEntityProvider create(KeycloakSession session) {
        return new Provider();
    }

    @Override
    public void init(Config.Scope config) {
        // no configuration
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // A deleted realm's rows go with it.
        factory.register(event -> {
            if (event instanceof RealmModel.RealmRemovedEvent e) {
                PasskeyStore.of(e.getKeycloakSession()).removeRealm(e.getRealm().getId());
                ImpersonatedStore.of(e.getKeycloakSession()).removeRealm(e.getRealm().getId());
            }
        });
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
