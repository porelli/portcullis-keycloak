package eu.portcullis.signin.store;

import eu.portcullis.signin.PasskeyClassifier;
import eu.portcullis.signin.StoredAttestation;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * The extension's own tables (plan D5, contract §8.1
 * {@code portcullis-passkey-store}) through the Keycloak session's JPA
 * {@link EntityManager}: every write joins the request's (or the task's)
 * transaction. Nothing here begins or commits one.
 */
public final class PasskeyStore {
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    private final EntityManager em;

    public PasskeyStore(EntityManager em) {
        this.em = Objects.requireNonNull(em);
    }

    /** The store of a Keycloak session. */
    public static PasskeyStore of(KeycloakSession s) {
        return new PasskeyStore(s.getProvider(JpaConnectionProvider.class).getEntityManager());
    }

    /** Stores a new passkey's attestation, classified now against {@code serial} (the file's {@code mds.serial} it was decided with). */
    public void put(RealmModel r, UserModel u, CredentialModel c, StoredAttestation a, String kind, String cappedAt, long serial) {
        put(r, u, c, a, kind, cappedAt, serial, Instant.now());
    }

    /** Stores a new passkey's attestation, classified against {@code serial} at {@code at}. */
    public void put(RealmModel r, UserModel u, CredentialModel c, StoredAttestation a, String kind, String cappedAt,
            long serial, Instant at) {
        if (r == null || u == null || c == null || c.getId() == null || a == null || a.fmt() == null
                || a.attStmtCbor() == null || a.authenticatorData() == null || a.aaguid() == null) {
            throw new IllegalArgumentException("passkey store: an incomplete row");
        }
        if (PasskeyClassifier.rank(kind) < 0 || (cappedAt != null && PasskeyClassifier.rank(cappedAt) < 0)) {
            throw new IllegalArgumentException("passkey store: not a passkey kind");
        }
        PasskeyEntity e = new PasskeyEntity();
        e.credentialId = c.getId();
        e.realmId = r.getId();
        e.userId = u.getId();
        e.aaguid = a.aaguid().toString();
        e.attFmt = a.fmt();
        e.attStmt = B64URL.encodeToString(a.attStmtCbor());
        e.authenticatorData = B64URL.encodeToString(a.authenticatorData());
        List<String> x5c = PasskeyClassifier.x5c(a);
        e.x5c = x5c.isEmpty() ? null : String.join(",", x5c);
        e.backupEligible = a.backupEligible();
        e.kind = kind;
        e.cappedAt = cappedAt;
        e.mdsSerial = serial;
        e.classifiedAt = at.toEpochMilli();
        em.persist(e);
    }

    public Optional<PasskeyEntity> get(String credentialId) {
        if (credentialId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(em.find(PasskeyEntity.class, credentialId));
    }

    /** Every row of a realm, by credential id (a list read at once: callers may change rows meanwhile). */
    public Stream<PasskeyEntity> all(RealmModel r) {
        List<PasskeyEntity> rows = em.createNamedQuery("portcullisPasskeysByRealm", PasskeyEntity.class)
                .setParameter("realmId", r.getId())
                .getResultList();
        return new ArrayList<>(rows).stream();
    }

    /** The row's attestation, as {@link PasskeyClassifier} reads it. */
    public static StoredAttestation attestation(PasskeyEntity e) {
        return new StoredAttestation(e.attFmt, B64URL_DEC.decode(e.attStmt), B64URL_DEC.decode(e.authenticatorData),
                UUID.fromString(e.aaguid), e.backupEligible);
    }

    /** Records a (re)classification: the kind, the serial it was decided against, now. */
    public void setKind(PasskeyEntity e, String kind, long serial) {
        if (PasskeyClassifier.rank(kind) < 0) {
            throw new IllegalArgumentException("passkey store: not a passkey kind");
        }
        e.kind = kind;
        e.mdsSerial = serial;
        e.classifiedAt = Instant.now().toEpochMilli();
        em.merge(e);
    }

    /** Removes one row; false when there was none. */
    public boolean remove(String credentialId) {
        PasskeyEntity e = credentialId == null ? null : em.find(PasskeyEntity.class, credentialId);
        if (e == null) {
            return false;
        }
        em.remove(e);
        return true;
    }

    private static final String CREDENTIAL_EXISTS =
            " exists (select c.id from CredentialEntity c where c.id = %1$s)"
                    + " or exists (select f.id from FederatedUserCredentialEntity f where f.id = %1$s)";

    /**
     * Removes the realm's rows whose Keycloak credential is gone (Keycloak
     * 26.8.1 has no credential-removal event): neither a
     * {@code CredentialEntity} (local and imported users) nor a
     * {@code FederatedUserCredentialEntity}. Returns how many.
     */
    public int removeOrphans(RealmModel r) {
        List<String> ids = em.createQuery(
                "select p.credentialId from PortcullisPasskey p where p.realmId = :realmId and not ("
                        + CREDENTIAL_EXISTS.formatted("p.credentialId") + ")", String.class)
                .setParameter("realmId", r.getId())
                .getResultList();
        int n = 0;
        for (String id : ids) {
            if (remove(id)) {
                n++;
            }
        }
        return n;
    }

    /** Whether Keycloak still has a credential of this id (local or federated). */
    public boolean credentialExists(String credentialId) {
        return !em.createQuery("select c.id from CredentialEntity c where c.id = :id", String.class)
                        .setParameter("id", credentialId).setMaxResults(1).getResultList().isEmpty()
                || !em.createQuery("select f.id from FederatedUserCredentialEntity f where f.id = :id", String.class)
                        .setParameter("id", credentialId).setMaxResults(1).getResultList().isEmpty();
    }

    /** Every row of a deleted realm (Keycloak's {@code RealmRemovedEvent}). */
    public void removeRealm(String realmId) {
        em.createQuery("delete from PortcullisPasskey p where p.realmId = :realmId").setParameter("realmId", realmId).executeUpdate();
        em.createQuery("delete from PortcullisSigninState s where s.realmId = :realmId").setParameter("realmId", realmId).executeUpdate();
    }

    /**
     * Startup check: the entities are registered with Keycloak's persistence
     * unit and the tables exist (throws otherwise).
     */
    public void selfCheck() {
        em.createNamedQuery("portcullisPasskeysByRealm", PasskeyEntity.class)
                .setParameter("realmId", "")
                .setMaxResults(0)
                .getResultList();
        em.find(SigninStateEntity.class, "");
        em.find(ImpersonatedEntity.class, "");
    }

    /** The last {@code mds.serial} reclassification applied in a realm; -1 before the first. */
    public long lastSerial(RealmModel r) {
        SigninStateEntity s = em.find(SigninStateEntity.class, r.getId());
        return s == null ? -1 : s.lastMdsSerial;
    }

    public void setLastSerial(RealmModel r, long serial) {
        SigninStateEntity s = em.find(SigninStateEntity.class, r.getId());
        if (s == null) {
            s = new SigninStateEntity();
            s.realmId = r.getId();
            s.lastMdsSerial = serial;
            em.persist(s);
        } else {
            s.lastMdsSerial = serial;
        }
    }
}
