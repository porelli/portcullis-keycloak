package eu.portcullis.signin.store;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

/**
 * A row of {@code PORTCULLIS_IMPERSONATED} (contract §8.1 "Ending"): a person
 * who has been signed in as, recorded at the start in the same transaction
 * as the session, so the expiry task finds their sessions whatever the file
 * says (unreadable, the record dropped) and after a restart. Removed by the
 * task once none of their sessions is impersonated. Never a user attribute:
 * core's LDAP federation is read-only, and nothing here reaches a token, the
 * account console or the user profile.
 */
@Entity(name = "PortcullisImpersonated")
@Table(name = "PORTCULLIS_IMPERSONATED")
@NamedQueries({
    @NamedQuery(name = "portcullisImpersonatedByRealm",
            query = "select i from PortcullisImpersonated i where i.realmId = :realmId order by i.userId"),
})
public class ImpersonatedEntity {
    @Id
    @Column(name = "USER_ID", length = 255)
    protected String userId;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    protected String realmId;

    @Column(name = "USERNAME", length = 255, nullable = false)
    protected String username;

    /** Epoch seconds of the latest start. */
    @Column(name = "SINCE", nullable = false)
    protected long since;
}
