package eu.portcullis.signin.store;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;

/**
 * The people's notice seen times ({@link NoticeSeenEntity}), over the
 * session's {@link EntityManager}: every write joins the request's
 * transaction; it never begins or commits one.
 */
public final class NoticeSeenStore {
    /** No notice seen yet. */
    public static final long NEVER = Long.MIN_VALUE;

    private final EntityManager em;

    public NoticeSeenStore(EntityManager em) {
        this.em = em;
    }

    public static NoticeSeenStore of(KeycloakSession s) {
        return new NoticeSeenStore(s.getProvider(JpaConnectionProvider.class).getEntityManager());
    }

    /** The latest end the person's notice showed (epoch milliseconds), or {@link #NEVER}. */
    public long seenUntil(String userId) {
        NoticeSeenEntity e = userId == null ? null : em.find(NoticeSeenEntity.class, userId);
        return e == null ? NEVER : e.seenUntil;
    }

    /** Moves the person's seen time forward to until; never back. */
    public void advance(String userId, long until) {
        NoticeSeenEntity e = em.find(NoticeSeenEntity.class, userId);
        if (e == null) {
            e = new NoticeSeenEntity();
            e.userId = userId;
            e.seenUntil = until;
            em.persist(e);
        } else if (until > e.seenUntil) {
            e.seenUntil = until;
        }
    }
}
