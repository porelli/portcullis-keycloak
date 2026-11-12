package eu.portcullis.signin;

import jakarta.ws.rs.core.HttpHeaders;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.events.Event;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * The event details the Hub's sign-in history reads (contract §8.1 "History
 * details", §8.2). They never hold a secret: method ids, a kind and the
 * User-Agent.
 *
 * <ul>
 * <li>{@link #onSuccess}: on the {@code LOGIN} event ({@code
 * portcullis-template}, at the end of the flow) — {@code pc_kind},
 * {@code pc_methods}, {@code pc_session}, {@code pc_ua};</li>
 * <li>{@link #onFailure}: before an authenticator checks a credential, so a
 * {@code LOGIN_ERROR} it raises carries {@code pc_method} (the method tried)
 * and {@code pc_ua}.</li>
 * <li>{@link #reapply}: a {@code LOGIN} that follows a required action is
 * sent by Keycloak in a later request with that request's event builder
 * ({@code LoginActionsService.processRequireAction} → {@code
 * AuthenticationManager.nextActionAfterAuthentication} → {@code
 * finishedRequiredActions}, Keycloak 26.8.1). {@code onSuccess} also keeps
 * its details in authentication notes; Portcullis' own required actions
 * ({@link PasskeyRegister}) put them back on {@code
 * RequiredActionContext.getEvent()} — the builder that request's {@code
 * LOGIN} is sent with — when they succeed. After a stock required action
 * the {@code LOGIN} has no {@code pc_kind} (the Hub: "the sign-in's methods
 * weren't recorded").</li>
 * </ul>
 * {@code pc_act} (sign-in part 3, F24): on a {@code LOGIN} in an impersonated
 * session — {@link Impersonation#of} the authentication's user session is
 * present — the administrator's username; one of {@link #SUCCESS_DETAILS},
 * so the re-apply carries it. A session that isn't impersonated never has
 * it (no empty value either).
 */
final class History {
    private History() {}

    static final String KIND = "pc_kind";
    static final String METHODS = "pc_methods";
    static final String SESSION = "pc_session";
    static final String UA = "pc_ua";
    static final String METHOD = "pc_method";
    static final String ACT = "pc_act";

    static final String SIGN_IN = "sign_in";
    static final String STEP_UP = "step_up";
    static final String SSO = "sso";

    /** The authentication notes {@link #onSuccess} keeps its details in ({@link #reapply}). */
    static final String NOTE_PREFIX = "portcullis.history.";
    static final List<String> SUCCESS_DETAILS = List.of(KIND, METHODS, SESSION, UA, ACT);
    /** Details written only with a value (never as {@code ""}). */
    private static final List<String> ONLY_WITH_VALUE = List.of(ACT);

    /** The longest {@code pc_ua} (characters). */
    static final int UA_MAX = 256;

    /**
     * The LOGIN event's details: kind, this authentication's new methods
     * (thisAuth) and all of the session's methods, each comma-joined in the
     * method table's order, and the User-Agent. A {@code pc_method} an
     * authenticator added before checking is dropped (it names a failure).
     */
    static void onSuccess(AuthenticationFlowContext c, Set<String> thisAuth, Set<String> session, String kind) {
        EventBuilder e = c.getEvent();
        if (e == null) {
            return;
        }
        e.removeDetail(METHOD);
        AuthenticationSessionModel a = c.getAuthenticationSession();
        Map<String, String> d = new HashMap<>(Map.of(KIND, kind == null ? "" : kind, METHODS, joined(thisAuth),
                SESSION, joined(session), UA, ua(c)));
        Impersonation.of(Impersonation.userSessionOf(c.getSession(), c.getRealm(), a, c.getUser()))
                .map(Impersonation.Info::admin)
                .ifPresent(admin -> d.put(ACT, admin));
        for (String key : SUCCESS_DETAILS) {
            String v = d.get(key);
            if (v == null && ONLY_WITH_VALUE.contains(key)) {
                e.removeDetail(key);
                if (a != null) {
                    a.removeAuthNote(NOTE_PREFIX + key);
                }
                continue;
            }
            put(e, key, v);
            if (a != null) {
                a.setAuthNote(NOTE_PREFIX + key, v);
            }
        }
    }

    /**
     * A Portcullis required action that succeeded: {@link #onSuccess}'s
     * details, kept in the authentication notes, back on the event builder
     * the following {@code LOGIN} is sent with. Nothing when this
     * authentication's flow didn't end in {@code portcullis-template}.
     */
    static void reapply(RequiredActionContext c) {
        reapply(c.getAuthenticationSession(), c.getEvent());
    }

    static void reapply(AuthenticationSessionModel a, EventBuilder e) {
        if (a == null || e == null || a.getAuthNote(NOTE_PREFIX + KIND) == null) {
            return;
        }
        e.removeDetail(METHOD);
        for (String key : SUCCESS_DETAILS) {
            String v = a.getAuthNote(NOTE_PREFIX + key);
            if ((v == null || v.isEmpty()) && ONLY_WITH_VALUE.contains(key)) {
                e.removeDetail(key);
                continue;
            }
            put(e, key, v == null ? "" : v);
        }
    }

    /** Before a check that may fail: the method tried and the User-Agent. */
    static void onFailure(AuthenticationFlowContext c, String method) {
        EventBuilder e = c.getEvent();
        if (e == null || method == null) {
            return;
        }
        put(e, METHOD, method);
        put(e, UA, ua(c));
    }

    /**
     * The kind of a sign-in that ended: {@code sso} when the SSO cookie
     * signed in and no method ran ({@code auth-cookie}'s note), {@code
     * step_up} when an SSO session gained a method, else {@code sign_in}.
     */
    static String kind(boolean ssoSession, Set<String> thisAuth) {
        if (ssoSession) {
            return thisAuth.isEmpty() ? SSO : STEP_UP;
        }
        return SIGN_IN;
    }

    /** The request's User-Agent: control characters removed, at most {@link #UA_MAX} characters. */
    static String ua(AuthenticationFlowContext c) {
        String raw = null;
        try {
            HttpRequest r = c.getHttpRequest();
            HttpHeaders h = r == null ? null : r.getHttpHeaders();
            raw = h == null ? null : h.getHeaderString(HttpHeaders.USER_AGENT);
        } catch (RuntimeException e) {
            raw = null;
        }
        return clean(raw);
    }

    static String clean(String raw) {
        if (raw == null) {
            return "";
        }
        StringBuilder b = new StringBuilder(Math.min(raw.length(), UA_MAX));
        for (int i = 0; i < raw.length() && b.length() < UA_MAX; i++) {
            char ch = raw.charAt(i);
            if (Character.isISOControl(ch)) {
                continue;
            }
            if (Character.isHighSurrogate(ch)) {
                // A pair is kept whole or not at all.
                if (i + 1 < raw.length() && Character.isLowSurrogate(raw.charAt(i + 1)) && b.length() + 2 <= UA_MAX) {
                    b.append(ch).append(raw.charAt(++i));
                } else if (i + 1 < raw.length() && Character.isLowSurrogate(raw.charAt(i + 1))) {
                    break;
                }
                continue;
            }
            if (Character.isLowSurrogate(ch)) {
                continue; // a lone half
            }
            b.append(ch);
        }
        return b.toString();
    }

    private static String joined(Set<String> methods) {
        StringBuilder b = new StringBuilder();
        for (String m : Methods.IDS) {
            if (methods != null && methods.contains(m)) {
                b.append(b.isEmpty() ? "" : ",").append(m);
            }
        }
        return b.toString();
    }

    /** Sets a detail, the empty string included (EventBuilder.detail ignores it). */
    private static void put(EventBuilder e, String key, String value) {
        if (value != null && !value.isEmpty()) {
            e.detail(key, value);
            return;
        }
        Event ev = e.getEvent();
        if (ev == null) {
            return;
        }
        Map<String, String> d = ev.getDetails();
        if (d == null) {
            d = new HashMap<>();
            ev.setDetails(d);
        }
        d.put(key, "");
    }
}
