package eu.portcullis.signin;

import eu.portcullis.signin.store.PasskeyStore;
import org.jboss.logging.Logger;
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
 * {@code portcullis-reclassify}: schedules {@link Reclassify} with Keycloak's
 * {@link TimerProvider} once the database migration is done (cluster aware:
 * one node runs it per interval).
 */
public final class ReclassifyFactory implements PortcullisTaskSpi.Factory, ProviderEventListener {
    public static final String PROVIDER_ID = Reclassify.TASK_NAME;
    private static final Logger LOG = Logger.getLogger(ReclassifyFactory.class);

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
            // Startup self-check: the store's entities reached Keycloak's
            // persistence unit and the changelog ran. Logged as an ERROR
            // naming portcullis (CI's smoke run fails on it).
            try {
                KeycloakModelUtils.runJobInTransaction(factory, s -> PasskeyStore.of(s).selfCheck());
            } catch (RuntimeException e) {
                LOG.errorf("portcullis: the passkey store isn't usable (%s): passkey registration and reclassification will fail",
                        e.getClass().getName());
            }
            KeycloakModelUtils.runJobInTransaction(factory, s -> {
                TimerProvider timer = s.getProvider(TimerProvider.class);
                timer.schedule(new ClusterAwareScheduledTaskRunner(factory, new Reclassify(), Reclassify.INTERVAL_MS),
                        Reclassify.INTERVAL_MS, Reclassify.TASK_NAME);
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
