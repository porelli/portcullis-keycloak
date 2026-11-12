package eu.portcullis.signin.store;

import jakarta.persistence.EntityManager;
import java.util.function.Consumer;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;

/**
 * The people's notice seen times ({@link NoticeSeenEntity}), over the
 * session's {@link EntityManager}: {@link #advance} joins the caller's
 * transaction; it never begins or commits one. {@link
 * #advanceInOwnTransaction} is the Continue's write: its own transaction,
 * run again once when it fails (two first Continues racing: the loser's
 * insert hits the primary key at commit, and the second run finds the
 * winner's row).
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

    /** Runs a job in its own committed transaction (Keycloak's {@code runJobInTransaction} in production). */
    @FunctionalInterface
    public interface Tx {
        void run(Consumer<EntityManager> job);
    }

    /**
     * {@link #advance} in its own transaction, tried twice. False (never an
     * exception) when both fail: the seen time stays, so the notice may be
     * shown again — toward telling.
     */
    public static boolean advanceInOwnTransaction(Tx tx, String userId, long until) {
        for (int attempt = 0; attempt < 2; attempt++) {
            try {
                tx.run(em -> new NoticeSeenStore(em).advance(userId, until));
                return true;
            } catch (RuntimeException e) {
                // a concurrent first insert (constraint at commit), or the database: once more, then give up
            }
        }
        return false;
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
