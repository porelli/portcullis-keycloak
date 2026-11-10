package eu.portcullis.signin.store;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

/**
 * A row of {@code PORTCULLIS_PASSKEY} (plan D5, contract §8.1
 * {@code portcullis-passkey-store}): one stored passkey's attestation and its
 * current kind, keyed by the Keycloak credential id. The statement and the
 * authenticator data are base64url (no padding); {@code x5c} is the
 * statement's chain, standard base64 DER joined by {@code ,}, leaf first.
 */
@Entity(name = "PortcullisPasskey")
@Table(name = "PORTCULLIS_PASSKEY")
@NamedQueries({
    @NamedQuery(name = "portcullisPasskeysByRealm",
            query = "select p from PortcullisPasskey p where p.realmId = :realmId order by p.credentialId"),
})
public class PasskeyEntity {
    @Id
    @Column(name = "CREDENTIAL_ID", length = 36)
    protected String credentialId;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    protected String realmId;

    @Column(name = "USER_ID", length = 255, nullable = false)
    protected String userId;

    @Column(name = "AAGUID", length = 36, nullable = false)
    protected String aaguid;

    @Column(name = "ATT_FMT", length = 32, nullable = false)
    protected String attFmt;

    @Column(name = "ATT_STMT", nullable = false)
    protected String attStmt;

    @Column(name = "AUTHENTICATOR_DATA", nullable = false)
    protected String authenticatorData;

    @Column(name = "X5C")
    protected String x5c;

    @Column(name = "BACKUP_ELIGIBLE", nullable = false)
    protected boolean backupEligible;

    @Column(name = "KIND", length = 32, nullable = false)
    protected String kind;

    @Column(name = "CAPPED_AT", length = 32)
    protected String cappedAt;

    @Column(name = "MDS_SERIAL", nullable = false)
    protected long mdsSerial;

    @Column(name = "CLASSIFIED_AT", nullable = false)
    protected long classifiedAt;

    public String getCredentialId() {
        return credentialId;
    }

    public String getRealmId() {
        return realmId;
    }

    public String getUserId() {
        return userId;
    }

    public String getAaguid() {
        return aaguid;
    }

    public String getAttFmt() {
        return attFmt;
    }

    public String getAttStmt() {
        return attStmt;
    }

    public String getAuthenticatorData() {
        return authenticatorData;
    }

    public String getX5c() {
        return x5c;
    }

    public boolean isBackupEligible() {
        return backupEligible;
    }

    /** The current kind: {@code passkey_synced}, {@code passkey_device} or {@code security_key}. */
    public String getKind() {
        return kind;
    }

    /** The add-stronger cap recorded at registration; null = none. */
    public String getCappedAt() {
        return cappedAt;
    }

    /** The {@code mds.serial} the kind was decided against. */
    public long getMdsSerial() {
        return mdsSerial;
    }

    /** When the kind was decided (epoch milliseconds). */
    public long getClassifiedAt() {
        return classifiedAt;
    }
}
