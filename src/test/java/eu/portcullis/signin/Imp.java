package eu.portcullis.signin;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.util.Time;
import org.keycloak.models.Constants;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;

/** Impersonated sessions and impersonation.json documents for the guard's and the expiry's tests. */
final class Imp {
    private Imp() {}

    static final String ID = ImpersonationFileTest.ID;
    static final String OTHER = ImpersonationFileTest.OLD;
    static final String REASON = "checking quota";
    /** Now, in Keycloak's clock (the completed executions' times are Time.currentTimeSeconds()). */
    static final Instant NOW = Instant.ofEpochSecond(Time.currentTimeSeconds());

    /** A file naming one running impersonation id of root as target, until NOW + 30 min, ended as given (JSON). */
    static ImpersonationFile file(String id, String target, String ended, String... clients) {
        return file(true, List.of(new Rec(id, target, NOW.plusSeconds(1800), ended)), clients);
    }

    record Rec(String id, String target, Instant until, String ended) {}

    static ImpersonationFile file(boolean allowed, List<Rec> recs, String... clients) {
        StringBuilder sessions = new StringBuilder();
        for (Rec r : recs) {
            sessions.append(sessions.length() == 0 ? "" : ",").append("""
                {"id": "%s", "admin": "root", "target": "%s", "reason": "%s", "started": "%s", "until": "%s", "ended": %s}"""
                    .formatted(r.id(), r.target(), REASON, NOW.minusSeconds(60), r.until(), r.ended()));
        }
        StringBuilder cs = new StringBuilder();
        for (String c : clients) {
            cs.append(cs.length() == 0 ? "" : ",").append('"').append(c).append('"');
        }
        String json = """
            {"version": 1, "allowed": %s, "written": "%s", "clients": [%s], "pending": [], "sessions": [%s], "notices": {}}
            """.formatted(allowed, NOW, cs, sessions);
        try {
            return ImpersonationFile.parse(json.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The notes ImpersonationResource writes (admin root, until NOW + 30 min) plus the given completed executions. */
    static Map<String, String> notes(Flow f, String id, Instant until, String... amrs) {
        Map<String, String> n = new HashMap<>();
        n.put(Constants.AUTHENTICATORS_COMPLETED, f.completedNote(amrs));
        n.put(Impersonation.ID, id);
        n.put(Impersonation.ADMIN, "root");
        n.put(Impersonation.UNTIL, String.valueOf(until.getEpochSecond()));
        n.put(Impersonation.REASON, REASON);
        return n;
    }

    /** A user session of p with these notes, id sid, registered as the flow's root authentication session's user session. */
    static UserSessionModel session(Flow f, Flow.Person p, String sid, Map<String, String> notes) {
        UserSessionModel us = Fake.named("session " + sid)
                .ret("getId", sid)
                .ret("getUser", p.model)
                .ret("getRealm", f.realm)
                .on("getNote", a -> notes.get((String) a[0]))
                .on("setNote", a -> notes.put((String) a[0], (String) a[1]))
                .as(UserSessionModel.class);
        f.userSessions.put(sid, us);
        return us;
    }

    /** alice's live impersonated session (root's methods: amrs), as the flow's root authentication session's. */
    static UserSessionModel alice(Flow f, Flow.Person alice, String... amrs) {
        return session(f, alice, f.rootId, notes(f, ID, NOW.plusSeconds(1800), amrs));
    }

    /** The guard's Keycloak calls: the identity cookie's session (null: none), and the sessions logged out. */
    static final class Ops implements ImpersonationGuard.Ops {
        UserSessionModel cookie;
        final List<String> loggedOut = new ArrayList<>();

        Ops(UserSessionModel cookie) {
            this.cookie = cookie;
        }

        @Override
        public AuthenticationManager.AuthResult identity(AuthenticationFlowContext c) {
            return cookie == null ? null : new AuthenticationManager.AuthResult(cookie.getUser(), cookie, null, null);
        }

        @Override
        public void logOut(AuthenticationFlowContext c, UserSessionModel us) {
            loggedOut.add(us.getId());
        }
    }
}
