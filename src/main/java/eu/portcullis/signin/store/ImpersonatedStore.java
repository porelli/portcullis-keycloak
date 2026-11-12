package eu.portcullis.signin.store;

import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.List;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * The people signed in as ({@link ImpersonatedEntity}), over the session's
 * {@link EntityManager}: every write joins the request's (or the task's)
 * transaction; it never begins or commits one.
 */
public final class ImpersonatedStore {
    /** A person signed in as: Keycloak's user id, the username at the start, the latest start (epoch seconds). */
    public record Mark(String userId, String username, long since) {}

    private final EntityManager em;

    public ImpersonatedStore(EntityManager em) {
        this.em = em;
    }

    public static ImpersonatedStore of(KeycloakSession s) {
        return new ImpersonatedStore(s.getProvider(JpaConnectionProvider.class).getEntityManager());
    }

    /** Records (or refreshes) that u is being signed in as from at. */
    public void mark(RealmModel r, UserModel u, Instant at) {
        ImpersonatedEntity e = em.find(ImpersonatedEntity.class, u.getId());
        if (e == null) {
            e = new ImpersonatedEntity();
            e.userId = u.getId();
            e.realmId = r.getId();
            e.username = u.getUsername();
            e.since = at.getEpochSecond();
            em.persist(e);
        } else {
            e.realmId = r.getId();
            e.username = u.getUsername();
            e.since = at.getEpochSecond();
        }
    }

    /** Everyone recorded in the realm. */
    public List<Mark> marked(RealmModel r) {
        return em.createNamedQuery("portcullisImpersonatedByRealm", ImpersonatedEntity.class)
                .setParameter("realmId", r.getId())
                .getResultList().stream()
                .map(e -> new Mark(e.userId, e.username, e.since))
                .toList();
    }

    /** Removes the record, unless a start refreshed it after since (a start racing the task keeps it). */
    public void unmark(String userId, long since) {
        ImpersonatedEntity e = em.find(ImpersonatedEntity.class, userId);
        if (e != null && e.since <= since) {
            em.remove(e);
        }
    }

    public void removeRealm(String realmId) {
        em.createQuery("delete from PortcullisImpersonated i where i.realmId = :realmId").setParameter("realmId", realmId).executeUpdate();
    }
}
