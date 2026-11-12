package eu.portcullis.signin;

import java.time.Duration;
import java.time.Instant;

/**
 * The banner of every Portcullis page in an impersonated session (D43):
 * "You are signed in as &lt;person&gt; (by &lt;admin&gt;) · reason
 * “&lt;reason&gt;” · &lt;n&gt; min left" and Stop, where n = ceil(remaining /
 * 60 s), at least 1. Values are escaped by the template.
 */
public final class ImpersonationBanner {
    private final String person;
    private final String admin;
    private final String reason;
    private final long minutesLeft;
    private final String stopUrl;

    private ImpersonationBanner(String person, String admin, String reason, long minutesLeft, String stopUrl) {
        this.person = person;
        this.admin = admin;
        this.reason = reason;
        this.minutesLeft = minutesLeft;
        this.stopUrl = stopUrl;
    }

    /** The banner of a session's impersonation i for person; null when the notes are partial. */
    static ImpersonationBanner of(Impersonation.Info i, String person, String stopUrl, Instant now) {
        if (i == null || i.admin() == null || i.reason() == null || i.until() == null) {
            return null;
        }
        long seconds = Math.max(0, Duration.between(now, i.until()).getSeconds());
        long minutes = Math.max(1, (seconds + 59) / 60);
        return new ImpersonationBanner(person, i.admin(), i.reason(), minutes, stopUrl);
    }

    public String getPerson() {
        return person;
    }

    public String getAdmin() {
        return admin;
    }

    public String getReason() {
        return reason;
    }

    public long getMinutesLeft() {
        return minutesLeft;
    }

    public String getStopUrl() {
        return stopUrl;
    }
}
