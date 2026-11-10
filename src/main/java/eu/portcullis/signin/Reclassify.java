package eu.portcullis.signin;

import eu.portcullis.signin.store.PasskeyEntity;
import eu.portcullis.signin.store.PasskeyStore;
import java.time.Instant;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.timer.ScheduledTask;

/**
 * {@code portcullis-reclassify} (contract §8.1, plan D14): every 5 minutes,
 * per realm, removes rows whose credential is gone and — when
 * {@code mds.serial} is above the last serial applied — classifies every
 * stored passkey again ({@link PasskeyClassifier#reclassify}). A change
 * rewrites the Keycloak credential's type in place and is logged
 * ({@code PasskeyReclassified}: username, AAGUID, the two kinds).
 */
public final class Reclassify implements ScheduledTask {
    private static final Logger LOG = Logger.getLogger(Reclassify.class);

    public static final String TASK_NAME = "portcullis-reclassify";
    public static final long INTERVAL_MS = 5 * 60 * 1000L;

    /** What happened to one credential's type. */
    sealed interface Outcome {
        /** The type was rewritten; the user's name for the log. */
        record Applied(String username) implements Outcome {}

        /** Keycloak confirms the credential no longer exists: the orphan sweep removes the row. */
        record Gone() implements Outcome {}

        /** Anything else (a lookup failed or found nothing unconfirmed): the pass stops. */
        record Failed(String why) implements Outcome {}
    }

    /** Rewrites a stored credential's type. */
    interface CredentialTypes {
        Outcome setType(String userId, String credentialId, String type);
    }

    @Override
    public String getTaskName() {
        return TASK_NAME;
    }

    @Override
    public void run(KeycloakSession s) {
        SigninConfig cfg = SigninConfig.current();
        Instant now = Instant.now();
        List<String> realms = s.realms().getRealmsStream().map(RealmModel::getId).toList();
        for (String id : realms) {
            sweep(s.getKeycloakSessionFactory(), id);
        }
        PasskeyStore store = PasskeyStore.of(s);
        for (String id : realms) {
            RealmModel realm = s.realms().getRealm(id);
            if (realm == null) {
                continue;
            }
            s.getContext().setRealm(realm);
            try {
                apply(store, realm, cfg, keycloakTypes(s, realm, store), now);
            } finally {
                s.getContext().setRealm(null);
            }
        }
    }

    /** The orphan sweep in its own transaction: a failure never blocks reclassification. */
    private static void sweep(KeycloakSessionFactory factory, String realmId) {
        try {
            KeycloakModelUtils.runJobInTransaction(factory, s -> {
                RealmModel realm = s.realms().getRealm(realmId);
                if (realm != null) {
                    int gone = PasskeyStore.of(s).removeOrphans(realm);
                    if (gone > 0) {
                        LOG.debugf("portcullis: %d passkey rows of removed credentials deleted in realm %s", gone, realm.getName());
                    }
                }
            });
        } catch (RuntimeException e) {
            LOG.warnf("portcullis: passkey orphan sweep failed in realm %s (%s); retried next run", realmId, e.getClass().getSimpleName());
        }
    }

    private static CredentialTypes keycloakTypes(KeycloakSession s, RealmModel realm, PasskeyStore store) {
        return (userId, credentialId, type) -> {
            try {
                UserModel u = s.users().getUserById(realm, userId);
                CredentialModel c = u == null ? null : u.credentialManager().getStoredCredentialById(credentialId);
                if (c == null) {
                    // Gone only when Keycloak's own tables confirm it; a
                    // federation that can't be reached isn't proof.
                    return store.credentialExists(credentialId) ? new Outcome.Failed("lookup found nothing") : new Outcome.Gone();
                }
                c.setType(type);
                u.credentialManager().updateStoredCredential(c); // Keycloak's stores write the type
                return new Outcome.Applied(u.getUsername());
            } catch (RuntimeException e) {
                return new Outcome.Failed(e.getClass().getSimpleName());
            }
        };
    }

    /**
     * One realm's pass. With {@code mds.serial} above the last applied one,
     * every row is classified again; otherwise only rows decided against an
     * older serial (a registration racing a list update). Nothing is touched
     * with {@link SigninConfig#DENY_ALL} (serial -1). The realm's serial
     * advances only when every change was applied: a failed lookup stops the
     * pass, and the next run tries again. Returns how many kinds changed.
     */
    static int apply(PasskeyStore store, RealmModel realm, SigninConfig cfg, CredentialTypes types, Instant now) {
        long serial = cfg.mdsSerial();
        if (serial < 0) {
            return 0;
        }
        boolean newer = serial > store.lastSerial(realm);
        int changed = 0;
        for (PasskeyEntity e : (Iterable<PasskeyEntity>) store.all(realm)::iterator) {
            if (!newer && e.getMdsSerial() >= serial) {
                continue;
            }
            String next;
            try {
                next = PasskeyClassifier.reclassify(e.getKind(), e.getCappedAt(), PasskeyStore.attestation(e), cfg, now);
            } catch (RuntimeException x) {
                next = e.getKind(); // an unreadable row keeps its kind
            }
            if (!next.equals(e.getKind())) {
                Outcome o = types.setType(e.getUserId(), e.getCredentialId(), PasskeyClassifier.typeOf(next));
                if (o instanceof Outcome.Gone) {
                    continue; // the orphan sweep removes the row
                }
                if (o instanceof Outcome.Failed f) {
                    LOG.warnf("portcullis: reclassification in realm %s stopped at AAGUID %s (%s); mds.serial %d not applied, retried next run",
                            realm.getName(), e.getAaguid(), f.why(), serial);
                    return changed;
                }
                LOG.infof("portcullis: PasskeyReclassified user %s AAGUID %s %s -> %s (mds.serial %d)",
                        ((Outcome.Applied) o).username(), e.getAaguid(), e.getKind(), next, serial);
                changed++;
            }
            store.setKind(e, next, serial);
        }
        if (newer) {
            store.setLastSerial(realm, serial);
        }
        return changed;
    }
}
