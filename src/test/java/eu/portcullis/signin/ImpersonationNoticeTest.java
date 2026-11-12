package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.RequiredActionContext.Status;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;

/** The person's notice at their next sign-in (contract §8.1 "The notice", D45, F12). */
class ImpersonationNoticeTest {
    static final Instant T0 = Instant.parse("2026-11-12T14:02:00Z");
    static final Instant T1 = T0.plusSeconds(26 * 60);
    static final Instant T2 = Instant.parse("2026-11-12T16:00:00Z");
    static final Instant T3 = T2.plusSeconds(5 * 60 + 10);

    static final String GITEA_NEXTCLOUD = """
        [{"name": "Gitea", "own_session": false}, {"name": "Nextcloud", "own_session": true}]""";

    /** A file with alice's two notices: root 14:02–14:28 (Gitea, Nextcloud), sam 16:00–16:05:10 (none). */
    static ImpersonationFile twoNotices(String firstReason) {
        return file("""
            {"alice": [
              {"id": "%s", "admin": "root", "started": "%s", "ended": "%s", "reason": %s, "apps": %s},
              {"id": "%s", "admin": "sam", "started": "%s", "ended": "%s", "reason": "fixing the calendar", "apps": []}]}
            """.formatted(Imp.ID, T0, T1, quote(firstReason), GITEA_NEXTCLOUD, Imp.OTHER, T2, T3));
    }

    static ImpersonationFile file(String notices) {
        String json = """
            {"version": 1, "allowed": true, "written": "%s", "clients": [], "pending": [], "sessions": [], "notices": %s}
            """.formatted(T3, notices);
        try {
            return ImpersonationFile.parse(json.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String quote(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    /** The seen table, in memory. */
    static final class Seen implements ImpersonationNotice.Seen {
        final Map<String, Long> rows = new HashMap<>();
        int writes;

        @Override
        public long seenUntil(KeycloakSession s, UserModel u) {
            return rows.getOrDefault(u.getId(), eu.portcullis.signin.store.NoticeSeenStore.NEVER);
        }

        @Override
        public void advance(KeycloakSession s, UserModel u, long until) {
            writes++;
            rows.merge(u.getId(), until, Math::max);
        }
    }

    /** A RequiredActionContext over a Flow's authentication session, its own (later) event builder and a log of completions. */
    static final class Action {
        final Flow signIn = new Flow();
        final Flow later = new Flow();
        final Flow.Person alice = signIn.person("u-alice", "alice");
        Status status;
        /** At each success(): whether the event builder already carried the sign-in's pc_kind (History.reapply first). */
        final List<String> kindAtSuccess = new ArrayList<>();
        final RequiredActionContext context;

        Action() {
            signIn.user = alice.model;
            context = Fake.named("required action")
                    .on("getAuthenticationSession", a -> signIn.authSession)
                    .on("getEvent", a -> later.event)
                    .on("getUser", a -> alice.model)
                    .on("success", a -> {
                        kindAtSuccess.add(later.eventDetails().get(History.KIND));
                        return status = Status.SUCCESS;
                    })
                    .on("challenge", a -> status = Status.CHALLENGE)
                    .on("ignore", a -> status = Status.IGNORE)
                    .on("getStatus", a -> status)
                    .on("getSession", a -> signIn.session)
                    .on("getRealm", a -> signIn.realm)
                    .on("form", a -> signIn.context.form())
                    .as(RequiredActionContext.class);
            History.onSuccess(signIn.context, Set.of("password"), Set.of("password"), "sign_in");
        }

        NoticePage page() {
            return (NoticePage) signIn.formAttributes.get(ImpersonationNotice.ATTRIBUTE);
        }
    }

    static ImpersonationNotice notice(ImpersonationFile f, Seen seen) {
        return new ImpersonationNotice(() -> f, seen, (s, r) -> null);
    }

    static final String LINE_1 = "root signed in as you on 12 Nov 2026 14:02 UTC for 26 min: checking quota. Apps opened: Gitea, Nextcloud."
            + " Nextcloud keeps its own session and may have stayed signed in longer.";
    static final String LINE_2 = "sam signed in as you on 12 Nov 2026 16:00 UTC for 6 min: fixing the calendar. Apps opened: none.";

    @Test
    void showsUnseenOnly() {
        Seen seen = new Seen();
        seen.rows.put("u-alice", T1.toEpochMilli());
        Action r = new Action();
        notice(twoNotices("checking quota"), seen).requiredActionChallenge(r.context);
        assertEquals(Status.CHALLENGE, r.status);
        assertEquals(ImpersonationNotice.PAGE, r.signIn.page);
        assertEquals(List.of(LINE_2), r.page().getLines());
        assertFalse(r.page().isGeneric());
        assertEquals(0, seen.writes, "showing stores nothing");

        // Never seen: both, oldest first.
        Action all = new Action();
        notice(twoNotices("checking quota"), new Seen()).requiredActionChallenge(all.context);
        assertEquals(List.of(LINE_1, LINE_2), all.page().getLines());
    }

    @Test
    void continueStoresSeen() {
        Seen seen = new Seen();
        ImpersonationNotice n = notice(twoNotices("checking quota"), seen);
        Action r = new Action();
        n.requiredActionChallenge(r.context);
        n.processAction(r.context);
        assertEquals(Status.SUCCESS, r.status);
        assertEquals(T3.toEpochMilli(), seen.rows.get("u-alice"));

        // A notice that arrived after the page was shown isn't marked seen: Continue stores what was shown.
        Seen s2 = new Seen();
        s2.rows.put("u-alice", T1.toEpochMilli() - 1);
        Action first = new Action();
        notice(file("""
            {"alice": [{"id": "%s", "admin": "root", "started": "%s", "ended": "%s", "reason": "checking quota", "apps": []}]}
            """.formatted(Imp.ID, T0, T1)), s2).requiredActionChallenge(first.context);
        notice(twoNotices("checking quota"), s2).processAction(first.context);
        assertEquals(Status.SUCCESS, first.status);
        assertEquals(T1.toEpochMilli(), s2.rows.get("u-alice"));

        // Never moved back.
        Seen s3 = new Seen();
        s3.rows.put("u-alice", T3.toEpochMilli() + 1000);
        Action again = new Action();
        again.signIn.authNotes.put(ImpersonationNotice.SHOWN_NOTE, String.valueOf(T1.toEpochMilli()));
        notice(twoNotices("checking quota"), s3).processAction(again.context);
        assertEquals(T3.toEpochMilli() + 1000, s3.rows.get("u-alice"));
    }

    @Test
    void nothingUnseenSilent() {
        Seen seen = new Seen();
        seen.rows.put("u-alice", T3.toEpochMilli());
        Action r = new Action();
        notice(twoNotices("checking quota"), seen).requiredActionChallenge(r.context);
        assertEquals(Status.SUCCESS, r.status);
        assertNull(r.signIn.page, "no form");
        assertEquals(0, seen.writes);

        // No notices for the person at all (a readable file): silent too.
        Action none = new Action();
        notice(file("{}"), new Seen()).requiredActionChallenge(none.context);
        assertEquals(Status.SUCCESS, none.status);
        assertNull(none.signIn.page);
    }

    @Test
    void unreadableFileGeneric() {
        Seen seen = new Seen();
        seen.rows.put("u-alice", T1.toEpochMilli());
        ImpersonationNotice n = notice(ImpersonationFile.DENY, seen);
        Action r = new Action();
        n.requiredActionChallenge(r.context);
        assertEquals(Status.CHALLENGE, r.status);
        assertEquals(ImpersonationNotice.PAGE, r.signIn.page);
        assertTrue(r.page().isGeneric());
        assertEquals(List.of(), r.page().getLines());
        n.processAction(r.context);
        assertEquals(Status.SUCCESS, r.status);
        assertEquals(T1.toEpochMilli(), seen.rows.get("u-alice"), "SEEN_UNTIL unchanged");
        assertEquals(0, seen.writes);
    }

    @Test
    void ignoredWhileImpersonated() {
        Seen seen = new Seen();
        Action r = new Action();
        org.keycloak.models.UserSessionModel imp = Imp.alice(r.signIn, r.alice, "hwk");
        ImpersonationNotice n = new ImpersonationNotice(() -> twoNotices("checking quota"), seen,
                (s, realm) -> new AuthenticationManager.AuthResult(r.alice.model, imp, null, null));
        n.requiredActionChallenge(r.context);
        assertEquals(Status.IGNORE, r.status);
        assertNull(r.signIn.page, "no form");
        assertEquals(0, seen.writes);
        assertTrue(r.kindAtSuccess.isEmpty(), "never completed");

        // The auth session's own user session impersonated (no identity cookie): ignored too.
        Action own = new Action();
        Imp.alice(own.signIn, own.alice, "hwk");
        notice(twoNotices("checking quota"), seen).requiredActionChallenge(own.context);
        assertEquals(Status.IGNORE, own.status);

        // A posted Continue in an impersonated session: refused, nothing stored, never completed.
        Action post = new Action();
        post.signIn.authNotes.put(ImpersonationNotice.SHOWN_NOTE, String.valueOf(T3.toEpochMilli()));
        Imp.alice(post.signIn, post.alice, "hwk");
        notice(twoNotices("checking quota"), seen).processAction(post.context);
        assertEquals(Status.CHALLENGE, post.status);
        assertEquals(ImpersonationResource.PAGE, post.signIn.page);
        assertEquals(0, seen.writes);
        assertTrue(post.kindAtSuccess.isEmpty());
    }

    @Test
    void reappliesHistory() {
        // The silent completion.
        Seen seen = new Seen();
        seen.rows.put("u-alice", T3.toEpochMilli());
        Action silent = new Action();
        notice(twoNotices("checking quota"), seen).requiredActionChallenge(silent.context);
        assertEquals(List.of("sign_in"), silent.kindAtSuccess);
        assertEquals("password", silent.later.eventDetails().get(History.METHODS));

        // Continue.
        ImpersonationNotice n = notice(twoNotices("checking quota"), new Seen());
        Action cont = new Action();
        n.requiredActionChallenge(cont.context);
        assertTrue(cont.kindAtSuccess.isEmpty());
        n.processAction(cont.context);
        assertEquals(List.of("sign_in"), cont.kindAtSuccess);
        assertEquals("password", cont.later.eventDetails().get(History.SESSION));

        // Continue past the generic page.
        ImpersonationNotice g = notice(ImpersonationFile.DENY, new Seen());
        Action generic = new Action();
        g.requiredActionChallenge(generic.context);
        g.processAction(generic.context);
        assertEquals(List.of("sign_in"), generic.kindAtSuccess);
    }

    @Test
    void lineExact() {
        ImpersonationFile.Notice n = new ImpersonationFile.Notice(Imp.ID, "root", T0, T1, "checking quota",
                List.of(new ImpersonationFile.App("Gitea", false), new ImpersonationFile.App("Nextcloud", true)));
        assertEquals(LINE_1, ImpersonationNotice.line(n));
        assertEquals("root signed in as you on 12 Nov 2026 14:02 UTC for 26 min: checking quota. Apps opened: Gitea.",
                ImpersonationNotice.line(new ImpersonationFile.Notice(Imp.ID, "root", T0, T1, "checking quota",
                        List.of(new ImpersonationFile.App("Gitea", false)))));
        // No app: "Apps opened: none."; minutes rounded up, at least 1; d without a leading zero.
        Instant may = Instant.parse("2026-05-03T09:07:30Z");
        assertEquals("sam signed in as you on 3 May 2026 09:07 UTC for 1 min: fixing the calendar. Apps opened: none.",
                ImpersonationNotice.line(new ImpersonationFile.Notice(Imp.ID, "sam", may, may, "fixing the calendar", List.of())));
        assertEquals("sam signed in as you on 3 May 2026 09:07 UTC for 2 min: fixing the calendar. Apps opened: none.",
                ImpersonationNotice.line(new ImpersonationFile.Notice(Imp.ID, "sam", may, may.plusSeconds(61), "fixing the calendar", List.of())));
        // Two apps with their own sessions: one sentence each.
        assertEquals("root signed in as you on 12 Nov 2026 14:02 UTC for 26 min: checking quota. Apps opened: Nextcloud, Immich."
                + " Nextcloud keeps its own session and may have stayed signed in longer."
                + " Immich keeps its own session and may have stayed signed in longer.",
                ImpersonationNotice.line(new ImpersonationFile.Notice(Imp.ID, "root", T0, T1, "checking quota",
                        List.of(new ImpersonationFile.App("Nextcloud", true), new ImpersonationFile.App("Immich", true)))));
    }

    @Test
    void reasonEscapedInPage() throws Exception {
        Action r = new Action();
        notice(twoNotices("<b>x</b> & \"q\""), new Seen()).requiredActionChallenge(r.context);
        String html = render(r.page());
        assertTrue(html.contains("root signed in as you on 12 Nov 2026 14:02 UTC for 26 min: &lt;b&gt;x&lt;/b&gt; &amp; &quot;q&quot;. Apps opened: Gitea, Nextcloud."),
                html);
        assertFalse(html.contains("<b>x</b>"), html);
        assertTrue(html.contains(LINE_2), html);
        assertTrue(html.contains("id=\"portcullis-impersonation-notice\""), html);
        assertTrue(html.contains("action=\"https://auth.example.com/realms/portcullis/login-actions/required-action?x=1&amp;y=2\""), html);
        assertTrue(html.contains("id=\"portcullis-notice-continue\""), html);
        assertTrue(html.contains("An administrator signed in as you"), "the heading: " + html);
        assertFalse(html.contains("Your Sign-in page"), html);

        String generic = render(NoticePage.generic());
        assertTrue(generic.contains("An administrator signed in as you. Your Sign-in page&#39;s history has the details."), generic);
        assertFalse(generic.contains("<li"), generic);
    }

    private static String render(NoticePage page) throws Exception {
        return NeedsStrongerTemplateTest.render(ImpersonationNotice.PAGE, Map.of(ImpersonationNotice.ATTRIBUTE, page,
                "url", Map.of("loginAction", "https://auth.example.com/realms/portcullis/login-actions/required-action?x=1&y=2")))
                .replaceAll("\\s+", " ");
    }
}
