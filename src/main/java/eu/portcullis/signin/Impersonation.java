package eu.portcullis.signin;

import java.net.URI;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Function;
import org.keycloak.models.ImpersonationSessionNote;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * An impersonated user session (contract §8.1 "Impersonation"): the notes
 * {@link ImpersonationResource} writes on the person's session, and the live
 * check against {@code impersonation.json}.
 */
final class Impersonation {
    private Impersonation() {}

    /** The impersonation's id (32 lowercase hex). Its presence alone marks the session as impersonated. */
    static final String ID = "portcullis.imp.id";
    /** The end, epoch seconds. */
    static final String UNTIL = "portcullis.imp.until";
    /** The administrator's typed reason: shown on the pages, never in a token, URL, event or log line. */
    static final String REASON = "portcullis.imp.reason";
    /** Keycloak's own note naming the impersonator (the admin console shows it). */
    static final String ADMIN = ImpersonationSessionNote.IMPERSONATOR_USERNAME.toString();

    /**
     * From the notes: the id, the administrator's username, the reason and
     * the end. {@code admin}, {@code reason} and {@code until} are null when
     * any of them is missing or unreadable (never live).
     */
    record Info(String id, String admin, String reason, Instant until) {}

    /** The session's impersonation, when it has {@link #ID}. */
    static Optional<Info> of(UserSessionModel s) {
        String id = s == null ? null : s.getNote(ID);
        if (id == null) {
            return Optional.empty();
        }
        String admin = s.getNote(ADMIN);
        String reason = s.getNote(REASON);
        String until = s.getNote(UNTIL);
        Instant end = null;
        try {
            end = until == null ? null : Instant.ofEpochSecond(Long.parseLong(until));
        } catch (RuntimeException e) {
            end = null;
        }
        if (admin == null || reason == null || end == null) {
            return Optional.of(new Info(id, null, null, null));
        }
        return Optional.of(new Info(id, admin, reason, end));
    }

    /**
     * The user session this authentication belongs to (Keycloak's: the
     * root authentication session's id is the user session's,
     * {@code AuthenticationSessionManager.getUserSession}), when it is the
     * authenticated person's; else null.
     */
    static UserSessionModel userSessionOf(KeycloakSession session, RealmModel realm, AuthenticationSessionModel a, UserModel user) {
        try {
            if (session == null || a == null || a.getParentSession() == null || session.sessions() == null) {
                return null;
            }
            UserSessionModel us = session.sessions().getUserSession(realm, a.getParentSession().getId());
            if (us == null || user == null || us.getUser() == null || !user.getId().equals(us.getUser().getId())) {
                return null;
            }
            return us;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Live: the file allows it, its {@code sessions} has the id and it hasn't
     * ended, the record's admin and target are the session's, and now is
     * before both the note's {@code until} and the record's.
     */
    static boolean live(Info i, String target, ImpersonationFile f, Instant now) {
        if (i == null || i.admin() == null || i.until() == null || target == null || f == null || now == null || !f.allowed()) {
            return false;
        }
        Optional<ImpersonationFile.SessionRec> rec = f.session(i.id());
        if (rec.isEmpty()) {
            return false;
        }
        ImpersonationFile.SessionRec r = rec.get();
        return r.ended() == null && r.admin().equals(i.admin()) && r.target().equals(target)
                && now.isBefore(i.until()) && now.isBefore(r.until());
    }

    /**
     * Stop: {@code https://people.<domain>/impersonation/stop}, from the
     * origin of the env {@code PORTCULLIS_SIGNIN_URL} (core: {@code
     * https://people.<domain>/signin}); null when it isn't an http(s) URL.
     */
    static String stopUrl(Function<String, String> env) {
        String v;
        try {
            v = env.apply(TemplateAuthenticator.SIGNIN_URL_ENV);
        } catch (RuntimeException e) {
            return null;
        }
        if (v == null) {
            return null;
        }
        try {
            URI u = new URI(v.trim());
            String scheme = u.getScheme();
            if (!("https".equals(scheme) || "http".equals(scheme)) || u.getRawAuthority() == null || u.getHost() == null
                    || u.getRawUserInfo() != null) {
                return null;
            }
            return scheme + "://" + u.getRawAuthority() + "/impersonation/stop";
        } catch (java.net.URISyntaxException e) {
            return null;
        }
    }
}
