package eu.portcullis.signin;

import java.time.Instant;
import eu.portcullis.signin.store.ImpersonatedStore;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.timer.ScheduledTask;

/**
 * {@code portcullis-impersonation-expiry} (contract §8.1 "Ending", D41):
 * every 15 s, per realm, walks the user sessions (online and offline) of
 * every person the extension recorded as signed in as
 * ({@code PORTCULLIS_IMPERSONATED}, written at the start in the same
 * transaction as the session: durable across restarts, shared by the
 * cluster), plus every person {@code impersonation.json} names (pending
 * included) — or, while the file can't be read, the last good file's — and
 * logs out ({@code backchannelLogout}, which also tells apps that registered
 * a backchannel logout) every session whose {@code portcullis.imp.id} isn't
 * live: ended, past its {@code until}, switched off, dropped from or unknown
 * to the file, or with partial notes. An unreadable file makes nothing live,
 * so every impersonated session ends (fail closed). Refresh-token grants
 * never pass the flows' guard: this task is what ends them. A session of the
 * person's own (no note) is never touched. A record is removed once none of
 * the person's sessions is impersonated and it is older than
 * {@link #MARK_GRACE_S} (a start racing the task keeps it). Logged with the
 * id and the person, never the reason.
 */
public final class ImpersonationExpiry implements ScheduledTask {
    private static final Logger LOG = Logger.getLogger(ImpersonationExpiry.class);

    public static final String TASK_NAME = "portcullis-impersonation-expiry";
    public static final long INTERVAL_MS = 15_000;
    /** A record younger than this is kept even with no impersonated session seen (its session may not be visible yet). */
    static final long MARK_GRACE_S = 60;

    /** Keycloak's calls (a test gives its own). */
    interface Ops {
        List<RealmModel> realms(KeycloakSession s);

        /** The person's online and offline user sessions in the realm (empty when unknown). */
        List<UserSessionModel> sessions(KeycloakSession s, RealmModel r, String username);

        /** The same by Keycloak's user id. */
        List<UserSessionModel> sessionsOf(KeycloakSession s, RealmModel r, String userId);

        /** The realm's {@code PORTCULLIS_IMPERSONATED} rows. */
        List<ImpersonatedStore.Mark> marked(KeycloakSession s, RealmModel r);

        /** Removes a row, unless a start refreshed it after since. */
        void unmark(KeycloakSession s, RealmModel r, String userId, long since);

        /** Logs the session out. */
        void logOut(KeycloakSession s, RealmModel r, UserSessionModel us);
    }

    static final Ops KEYCLOAK = new Ops() {
        @Override
        public List<RealmModel> realms(KeycloakSession s) {
            return s.realms().getRealmsStream().toList();
        }

        @Override
        public List<UserSessionModel> sessions(KeycloakSession s, RealmModel r, String username) {
            s.getContext().setRealm(r);
            return of(s, r, s.users().getUserByUsername(r, username));
        }

        @Override
        public List<UserSessionModel> sessionsOf(KeycloakSession s, RealmModel r, String userId) {
            s.getContext().setRealm(r);
            return of(s, r, s.users().getUserById(r, userId));
        }

        private List<UserSessionModel> of(KeycloakSession s, RealmModel r, UserModel u) {
            if (u == null) {
                return List.of();
            }
            return Stream.concat(s.sessions().getUserSessionsStream(r, u), s.sessions().getOfflineUserSessionsStream(r, u)).toList();
        }

        @Override
        public List<ImpersonatedStore.Mark> marked(KeycloakSession s, RealmModel r) {
            return ImpersonatedStore.of(s).marked(r);
        }

        @Override
        public void unmark(KeycloakSession s, RealmModel r, String userId, long since) {
            ImpersonatedStore.of(s).unmark(userId, since);
        }

        @Override
        public void logOut(KeycloakSession s, RealmModel r, UserSessionModel us) {
            logOutAlone(s.getKeycloakSessionFactory(), r.getId(), us.getId(), us.isOffline());
        }
    };
    /**
     * Keycloak's backchannel logout of one session in its own transaction
     * (a failure never stops the others); when it fails — a background task
     * has no request — the session is removed outright in another one.
     */
    static void logOutAlone(KeycloakSessionFactory factory, String realmId, String sessionId, boolean offline) {
        try {
            KeycloakModelUtils.runJobInTransaction(factory, ks -> {
                RealmModel realm = ks.realms().getRealm(realmId);
                if (realm == null) {
                    return;
                }
                ks.getContext().setRealm(realm);
                UserSessionModel us = offline ? ks.sessions().getOfflineUserSession(realm, sessionId) : ks.sessions().getUserSession(realm, sessionId);
                if (us != null) {
                    AuthenticationManager.backchannelLogout(ks, realm, us, orNull(() -> ks.getContext().getUri()),
                            orNull(() -> ks.getContext().getConnection()), orNull(() -> ks.getContext().getHttpRequest().getHttpHeaders()), true);
                }
            });
        } catch (RuntimeException e) {
            LOG.warnf("portcullis: the backchannel logout of an impersonated session failed (%s); removing the session",
                    e.getClass().getSimpleName());
            KeycloakModelUtils.runJobInTransaction(factory, ks -> {
                RealmModel realm = ks.realms().getRealm(realmId);
                if (realm == null) {
                    return;
                }
                UserSessionModel us = offline ? ks.sessions().getOfflineUserSession(realm, sessionId) : ks.sessions().getUserSession(realm, sessionId);
                if (us != null) {
                    if (offline) {
                        ks.sessions().removeOfflineUserSession(realm, us);
                    } else {
                        ks.sessions().removeUserSession(realm, us);
                    }
                }
            });
        }
    }

    private static <T> T orNull(Supplier<T> s) {
        try {
            return s.get();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private final Supplier<ImpersonationFile> file;
    private final Supplier<Instant> clock;
    private final Ops ops;
    /** The persons the last readable file named (walked while the file can't be read). */
    private volatile Set<String> lastTargets = Set.of();

    public ImpersonationExpiry() {
        this(ImpersonationFile::current, Instant::now, KEYCLOAK);
    }

    ImpersonationExpiry(Supplier<ImpersonationFile> file, Supplier<Instant> clock, Ops ops) {
        this.file = file;
        this.clock = clock;
        this.ops = ops;
    }

    @Override
    public String getTaskName() {
        return TASK_NAME;
    }

    @Override
    public void run(KeycloakSession s) {
        ImpersonationFile f = file.get();
        Instant now = clock.get();
        Set<String> named;
        if (f == ImpersonationFile.DENY) {
            named = lastTargets; // unreadable: nothing is live, every impersonated session ends
        } else {
            named = f.targets();
            lastTargets = named;
        }
        for (RealmModel realm : ops.realms(s)) {
            try {
                sweep(s, realm, f, now, named);
            } catch (RuntimeException e) {
                LOG.warnf("portcullis: impersonation expiry in realm %s failed (%s); retried next run", realm.getName(),
                        e.getClass().getSimpleName());
            }
        }
    }

    /** One realm: the recorded people (by id), then the file's (by username); never an early return. */
    private void sweep(KeycloakSession s, RealmModel realm, ImpersonationFile f, Instant now, Set<String> named) {
        Set<String> done = new HashSet<>();
        for (ImpersonatedStore.Mark m : ops.marked(s, realm)) {
            int left = walk(s, realm, f, now, m.username(), () -> ops.sessionsOf(s, realm, m.userId()), done);
            if (left == 0 && m.since() <= now.getEpochSecond() - MARK_GRACE_S) {
                ops.unmark(s, realm, m.userId(), m.since());
            }
        }
        for (String target : named) {
            walk(s, realm, f, now, target, () -> ops.sessions(s, realm, target), done);
        }
    }

    /**
     * Logs out the person's non-live impersonated sessions; returns how many
     * impersonated sessions are left (live ones, failed logouts, or -1 when
     * the sessions can't be read).
     */
    private int walk(KeycloakSession s, RealmModel realm, ImpersonationFile f, Instant now, String who,
            Supplier<List<UserSessionModel>> read, Set<String> done) {
        List<UserSessionModel> sessions;
        try {
            sessions = new ArrayList<>(read.get());
        } catch (RuntimeException e) {
            LOG.warnf("portcullis: impersonation expiry: the sessions of %s in realm %s can't be read (%s); retried next run",
                    who, realm.getName(), e.getClass().getSimpleName());
            return -1;
        }
        int left = 0;
        for (UserSessionModel us : sessions) {
            Optional<Impersonation.Info> i = Impersonation.of(us);
            if (i.isEmpty()) {
                continue;
            }
            if (!done.add(us.getId())) {
                left++; // seen in this run already (logged out, or live)
                continue;
            }
            String person = us.getUser() == null ? null : us.getUser().getUsername();
            if (Impersonation.live(i.get(), person, f, now)) {
                left++;
                continue;
            }
            try {
                ops.logOut(s, realm, us);
                LOG.infof("portcullis: impersonation %s ended: %s's session logged out", i.get().id(), person);
            } catch (RuntimeException e) {
                left++;
                LOG.warnf("portcullis: impersonation %s: %s's session couldn't be logged out (%s); retried next run",
                        i.get().id(), person, e.getClass().getSimpleName());
            }
        }
        return left;
    }
}
