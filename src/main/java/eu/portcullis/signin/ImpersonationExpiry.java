package eu.portcullis.signin;

import java.time.Instant;
import java.util.ArrayList;
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
 * every person {@code impersonation.json} names — or, while the file can't
 * be read, of the last good file's persons — and logs out
 * ({@code backchannelLogout}, which also tells apps that registered a
 * backchannel logout) every session whose {@code portcullis.imp.id} isn't
 * live: ended, past its {@code until}, switched off, unknown to the file,
 * or with partial notes. An unreadable file makes nothing live, so every
 * impersonated session of those persons ends (fail closed). A session of
 * the person's own (no note) is never touched. Logged with the id and the
 * person, never the reason.
 */
public final class ImpersonationExpiry implements ScheduledTask {
    private static final Logger LOG = Logger.getLogger(ImpersonationExpiry.class);

    public static final String TASK_NAME = "portcullis-impersonation-expiry";
    public static final long INTERVAL_MS = 15_000;

    /** Keycloak's calls (a test gives its own). */
    interface Ops {
        List<RealmModel> realms(KeycloakSession s);

        /** The person's online and offline user sessions in the realm (empty when unknown). */
        List<UserSessionModel> sessions(KeycloakSession s, RealmModel r, String username);

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
            UserModel u = s.users().getUserByUsername(r, username);
            if (u == null) {
                return List.of();
            }
            return Stream.concat(s.sessions().getUserSessionsStream(r, u), s.sessions().getOfflineUserSessionsStream(r, u)).toList();
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
        Set<String> targets;
        if (f == ImpersonationFile.DENY) {
            targets = lastTargets; // unreadable: nothing is live, every impersonated session of these ends
        } else {
            targets = f.targets();
            lastTargets = targets;
        }
        if (targets.isEmpty()) {
            return;
        }
        for (RealmModel realm : ops.realms(s)) {
            for (String target : targets) {
                List<UserSessionModel> sessions;
                try {
                    sessions = new ArrayList<>(ops.sessions(s, realm, target));
                } catch (RuntimeException e) {
                    LOG.warnf("portcullis: impersonation expiry: the sessions of %s in realm %s can't be read (%s); retried next run",
                            target, realm.getName(), e.getClass().getSimpleName());
                    continue;
                }
                for (UserSessionModel us : sessions) {
                    Optional<Impersonation.Info> i = Impersonation.of(us);
                    if (i.isEmpty()) {
                        continue;
                    }
                    String person = us.getUser() == null ? null : us.getUser().getUsername();
                    if (Impersonation.live(i.get(), person, f, now)) {
                        continue;
                    }
                    try {
                        ops.logOut(s, realm, us);
                        LOG.infof("portcullis: impersonation %s ended: %s's session logged out", i.get().id(), person);
                    } catch (RuntimeException e) {
                        LOG.warnf("portcullis: impersonation %s: %s's session couldn't be logged out (%s); retried next run",
                                i.get().id(), person, e.getClass().getSimpleName());
                    }
                }
            }
        }
    }
}
