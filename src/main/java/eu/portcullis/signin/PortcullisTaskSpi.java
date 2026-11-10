package eu.portcullis.signin;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * The extension's own SPI {@code portcullis-task}: factories that schedule
 * background work ({@code portcullis-reclassify}). Its providers do nothing
 * per session.
 */
public final class PortcullisTaskSpi implements Spi {
    /** A per-session handle of a background task (nothing to do). */
    public interface Task extends Provider {}

    /** A factory of the SPI. */
    public interface Factory extends ProviderFactory<Task> {}

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return "portcullis-task";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return Task.class;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return Factory.class;
    }
}
