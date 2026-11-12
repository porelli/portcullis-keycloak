package eu.portcullis.signin;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.provider.ProviderEvent;
import org.keycloak.provider.ProviderEventListener;
import org.keycloak.services.scheduled.ClusterAwareScheduledTaskRunner;
import org.keycloak.timer.TimerProvider;

/**
 * {@code portcullis-impersonation-expiry}: schedules {@link ImpersonationExpiry}
 * with Keycloak's {@link TimerProvider} once the database migration is done
 * (cluster aware: one node runs it per interval), every 15 s.
 */
public final class ImpersonationExpiryFactory implements PortcullisTaskSpi.Factory, ProviderEventListener {
    public static final String PROVIDER_ID = ImpersonationExpiry.TASK_NAME;

    private static final PortcullisTaskSpi.Task NOTHING = () -> {};

    private KeycloakSessionFactory factory;

    @Override
    public PortcullisTaskSpi.Task create(KeycloakSession session) {
        return NOTHING;
    }

    @Override
    public void init(Config.Scope config) {
        // no configuration
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        this.factory = factory;
        factory.register(this);
    }

    @Override
    public void onEvent(ProviderEvent event) {
        if (event instanceof PostMigrationEvent) {
            KeycloakModelUtils.runJobInTransaction(factory, s -> {
                TimerProvider timer = s.getProvider(TimerProvider.class);
                timer.schedule(new ClusterAwareScheduledTaskRunner(factory, new ImpersonationExpiry(), ImpersonationExpiry.INTERVAL_MS),
                        ImpersonationExpiry.INTERVAL_MS, ImpersonationExpiry.TASK_NAME);
            });
        }
    }

    @Override
    public void close() {
        if (factory != null) {
            factory.unregister(this);
        }
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
