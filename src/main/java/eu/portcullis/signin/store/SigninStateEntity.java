package eu.portcullis.signin.store;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** A row of {@code PORTCULLIS_SIGNIN_STATE}: per realm, the last {@code mds.serial} reclassification applied. */
@Entity(name = "PortcullisSigninState")
@Table(name = "PORTCULLIS_SIGNIN_STATE")
public class SigninStateEntity {
    @Id
    @Column(name = "REALM_ID", length = 36)
    protected String realmId;

    @Column(name = "LAST_MDS_SERIAL", nullable = false)
    protected long lastMdsSerial;
}
