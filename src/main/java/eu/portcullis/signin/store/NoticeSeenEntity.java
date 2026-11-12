package eu.portcullis.signin.store;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * A row of {@code PORTCULLIS_IMP_NOTICE_SEEN} (contract §8.1 "The notice"):
 * per person, the latest impersonation end their notice showed and they
 * continued past. Never a user attribute: core's LDAP federation is
 * read-only, and nothing here reaches a token, the account console or the
 * user profile.
 */
@Entity(name = "PortcullisImpNoticeSeen")
@Table(name = "PORTCULLIS_IMP_NOTICE_SEEN")
public class NoticeSeenEntity {
    @Id
    @Column(name = "USER_ID", length = 255)
    protected String userId;

    /** Epoch milliseconds of the latest {@code ended} shown. */
    @Column(name = "SEEN_UNTIL", nullable = false)
    protected long seenUntil;
}
