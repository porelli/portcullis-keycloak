package eu.portcullis.signin;

import eu.portcullis.signin.store.PasskeyEntity;
import eu.portcullis.signin.store.PasskeyStore;
import java.time.Instant;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
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

    /** Rewrites a stored credential's type; the username, or empty when the user or credential is gone. */
    interface CredentialTypes {
        Optional<String> setType(String userId, String credentialId, String type);
    }

    @Override
    public String getTaskName() {
        return TASK_NAME;
    }

    @Override
    public void run(KeycloakSession s) {
        SigninConfig cfg = SigninConfig.current();
        PasskeyStore store = PasskeyStore.of(s);
        Instant now = Instant.now();
        s.realms().getRealmsStream().forEach(realm -> {
            s.getContext().setRealm(realm);
            try {
                int gone = store.removeOrphans(realm);
                if (gone > 0) {
                    LOG.debugf("portcullis: %d passkey rows of removed credentials deleted in realm %s", gone, realm.getName());
                }
                apply(store, realm, cfg, keycloakTypes(s, realm), now);
            } finally {
                s.getContext().setRealm(null);
            }
        });
    }

    private static CredentialTypes keycloakTypes(KeycloakSession s, RealmModel realm) {
        return (userId, credentialId, type) -> {
            UserModel u = s.users().getUserById(realm, userId);
            if (u == null) {
                return Optional.empty();
            }
            CredentialModel c = u.credentialManager().getStoredCredentialById(credentialId);
            if (c == null) {
                return Optional.empty();
            }
            c.setType(type);
            u.credentialManager().updateStoredCredential(c); // Keycloak's stores write the type
            return Optional.of(u.getUsername());
        };
    }

    /**
     * One realm's pass. Nothing is touched when the serial isn't above the
     * last applied one, or with {@link SigninConfig#DENY_ALL} (serial -1).
     * Returns how many kinds changed.
     */
    static int apply(PasskeyStore store, RealmModel realm, SigninConfig cfg, CredentialTypes types, Instant now) {
        long serial = cfg.mdsSerial();
        if (serial < 0 || serial <= store.lastSerial(realm)) {
            return 0;
        }
        int changed = 0;
        for (PasskeyEntity e : (Iterable<PasskeyEntity>) store.all(realm)::iterator) {
            String next;
            try {
                next = PasskeyClassifier.reclassify(e.getKind(), e.getCappedAt(), PasskeyStore.attestation(e), cfg, now);
            } catch (RuntimeException x) {
                next = e.getKind(); // an unreadable row keeps its kind
            }
            if (!next.equals(e.getKind())) {
                Optional<String> user = types.setType(e.getUserId(), e.getCredentialId(), PasskeyClassifier.typeOf(next));
                if (user.isEmpty()) {
                    continue; // the credential is gone: the orphan sweep removes the row
                }
                LOG.infof("portcullis: PasskeyReclassified user %s AAGUID %s %s -> %s (mds.serial %d)",
                        user.get(), e.getAaguid(), e.getKind(), next, serial);
                changed++;
            }
            store.setKind(e, next, serial);
        }
        store.setLastSerial(realm, serial);
        return changed;
    }
}
