package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;

/** ImpersonationGuard (contract §8.1 "What an impersonated session may do in Keycloak", D42, F13). */
class ImpersonationGuardTest {
    static final ImpersonationFile LIVE = Imp.file(Imp.ID, "alice", "null", "portcullis-forward-auth", "nextcloud");

    private static ImpersonationGuard.Result check(Flow f, ImpersonationFile file, Imp.Ops ops, ImpersonationGuard.Stage stage) {
        return ImpersonationGuard.check(f.context, () -> file, Imp.NOW, ops, stage);
    }

    /** A flow for client with alice's live impersonated cookie session (root's methods: hwk). */
    private static Flow aliceFlow(String client) {
        Flow f = new Flow();
        f.clientId = client;
        return f;
    }

    @Test
    void notImpersonatedUntouched() {
        for (String client : List.of("portcullis-forward-auth", "nextcloud", "portcullis-fresh-auth", "account-console", "portcullis-ai-x")) {
            Flow f = aliceFlow(client);
            Flow.Person alice = f.person("u-alice", "alice");
            UserSessionModel plain = f.userSession(alice, "hwk");
            Imp.Ops ops = new Imp.Ops(plain);
            for (ImpersonationGuard.Stage s : ImpersonationGuard.Stage.values()) {
                assertEquals(ImpersonationGuard.Verdict.NOT_IMPERSONATED, check(f, LIVE, ops, s).verdict(), client);
                assertEquals(ImpersonationGuard.Verdict.NOT_IMPERSONATED, check(f, ImpersonationFile.DENY, ops, s).verdict(), client);
            }
            assertEquals(ImpersonationGuard.Verdict.NOT_IMPERSONATED,
                    check(f, LIVE, new Imp.Ops(null), ImpersonationGuard.Stage.COOKIE).verdict(), "no cookie");
            assertTrue(ops.loggedOut.isEmpty());
        }
    }

    @Test
    void liveListedSsoAllowed() {
        Flow f = aliceFlow("portcullis-forward-auth");
        Imp.Ops ops = new Imp.Ops(Imp.alice(f, f.person("u-alice", "alice"), "hwk"));
        ImpersonationGuard.Result r = check(f, LIVE, ops, ImpersonationGuard.Stage.COOKIE);
        assertEquals(ImpersonationGuard.Verdict.ALLOW, r.verdict());
        assertEquals("alice", r.person());
        assertEquals("root", r.info().admin());
    }

    @Test
    void unreadableFileEnds() {
        Flow f = aliceFlow("portcullis-forward-auth");
        UserSessionModel us = Imp.alice(f, f.person("u-alice", "alice"), "hwk");
        Imp.Ops ops = new Imp.Ops(us);
        assertEquals(ImpersonationGuard.Verdict.ENDED, check(f, ImpersonationFile.DENY, ops, ImpersonationGuard.Stage.COOKIE).verdict());
        assertEquals(List.of(us.getId()), ops.loggedOut, "logged out before answering");
    }

    @Test
    void notLiveEnds() {
        // Ended in the file, switched off, past until (note or record), another admin, an unknown id: all ENDED and logged out.
        Map<String, ImpersonationFile> files = Map.of(
                "ended", Imp.file(Imp.ID, "alice", "\"" + Imp.NOW.minusSeconds(5) + "\"", "portcullis-forward-auth"),
                "switched off", Imp.file(false, List.of(new Imp.Rec(Imp.ID, "alice", Imp.NOW.plusSeconds(1800), "null")), "portcullis-forward-auth"),
                "record until past", Imp.file(true, List.of(new Imp.Rec(Imp.ID, "alice", Imp.NOW.minusSeconds(1), "null")), "portcullis-forward-auth"),
                "another target", Imp.file(Imp.ID, "bob", "null", "portcullis-forward-auth"),
                "unknown id", Imp.file(Imp.OTHER, "alice", "null", "portcullis-forward-auth"));
        files.forEach((what, file) -> {
            Flow f = aliceFlow("portcullis-forward-auth");
            Imp.Ops ops = new Imp.Ops(Imp.alice(f, f.person("u-alice", "alice"), "hwk"));
            assertEquals(ImpersonationGuard.Verdict.ENDED, check(f, file, ops, ImpersonationGuard.Stage.COOKIE).verdict(), what);
            assertEquals(1, ops.loggedOut.size(), what);
        });
        Flow f = aliceFlow("portcullis-forward-auth");
        Imp.Ops ops = new Imp.Ops(Imp.session(f, f.person("u-alice", "alice"), f.rootId,
                Imp.notes(f, Imp.ID, Imp.NOW.minusSeconds(1), "hwk")));
        assertEquals(ImpersonationGuard.Verdict.ENDED, check(f, LIVE, ops, ImpersonationGuard.Stage.COOKIE).verdict(), "note until past");
    }

    /** Review M4: partial or inconsistent notes never reach a LOGIN: ended (and logged out), never allowed. */
    @Test
    void partialNotesEnd() {
        for (String drop : List.of(Impersonation.ADMIN, Impersonation.UNTIL, Impersonation.REASON)) {
            Flow f = aliceFlow("portcullis-forward-auth");
            Map<String, String> notes = Imp.notes(f, Imp.ID, Imp.NOW.plusSeconds(1800), "hwk");
            notes.remove(drop);
            Imp.Ops ops = new Imp.Ops(Imp.session(f, f.person("u-alice", "alice"), f.rootId, notes));
            for (ImpersonationGuard.Stage s : ImpersonationGuard.Stage.values()) {
                assertEquals(ImpersonationGuard.Verdict.ENDED, check(f, LIVE, ops, s).verdict(), drop);
            }
            assertFalse(ops.loggedOut.isEmpty(), drop);
        }
        Flow f = aliceFlow("portcullis-forward-auth");
        Map<String, String> notes = Imp.notes(f, Imp.ID, Imp.NOW.plusSeconds(1800), "hwk");
        notes.put(Impersonation.UNTIL, "soon");
        Imp.Ops ops = new Imp.Ops(Imp.session(f, f.person("u-alice", "alice"), f.rootId, notes));
        assertEquals(ImpersonationGuard.Verdict.ENDED, check(f, LIVE, ops, ImpersonationGuard.Stage.COOKIE).verdict(), "unreadable until");
        Flow g = aliceFlow("portcullis-forward-auth");
        Map<String, String> other = Imp.notes(g, Imp.ID, Imp.NOW.plusSeconds(1800), "hwk");
        other.put(Impersonation.ADMIN, "sam"); // the file says root
        Imp.Ops o2 = new Imp.Ops(Imp.session(g, g.person("u-alice", "alice"), g.rootId, other));
        assertEquals(ImpersonationGuard.Verdict.ENDED, check(g, LIVE, o2, ImpersonationGuard.Stage.COOKIE).verdict(), "another admin");
    }

    @Test
    void onlyNoticeActionAllowed() {
        Flow f = aliceFlow("portcullis-forward-auth");
        Flow.Person alice = f.person("u-alice", "alice");
        alice.fake.on("getRequiredActionsStream", a -> Stream.of(ImpersonationResource.NOTICE_ACTION));
        Imp.Ops ops = new Imp.Ops(Imp.alice(f, alice, "hwk"));
        assertEquals(ImpersonationGuard.Verdict.ALLOW, check(f, LIVE, ops, ImpersonationGuard.Stage.COOKIE).verdict());
        alice.fake.on("getRequiredActionsStream", a -> Stream.of(ImpersonationResource.NOTICE_ACTION, "UPDATE_PASSWORD"));
        assertEquals(ImpersonationGuard.Verdict.REFUSE, check(f, LIVE, ops, ImpersonationGuard.Stage.COOKIE).verdict());
        alice.fake.on("getRequiredActionsStream", a -> Stream.of());
        // An application-initiated action (kc_action) is a required action too.
        f.clientNotes.put(org.keycloak.models.Constants.KC_ACTION, "webauthn-register-passwordless");
        assertEquals(ImpersonationGuard.Verdict.REFUSE, check(f, LIVE, ops, ImpersonationGuard.Stage.COOKIE).verdict());
        assertTrue(ops.loggedOut.isEmpty(), "a refusal never logs out");
    }

    @Test
    void refusedRequests() {
        // Each: a request an impersonated session may not make → REFUSE.
        Map<String, java.util.function.Consumer<Flow>> cases = new java.util.LinkedHashMap<>();
        cases.put("unlisted client", f -> f.clientId = "account-console");
        cases.put("fresh-auth", f -> f.clientId = "portcullis-fresh-auth");
        cases.put("pc_method", f -> f.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key"));
        cases.put("a step's pc_method", f -> f.authNotes.put(PcMethod.STEP_NOTE, "yubikey_cert"));
        cases.put("prompt=login", f -> f.clientNotes.put("prompt", "consent login"));
        cases.put("max_age", f -> f.clientNotes.put("max_age", "0"));
        cases.put("acr", f -> f.clientNotes.put(org.keycloak.models.Constants.REQUESTED_LEVEL_OF_AUTHENTICATION, "2"));
        cases.put("essential acr", f -> f.clientNotes.put(org.keycloak.models.Constants.FORCE_LEVEL_OF_AUTHENTICATION, "true"));
        cases.put("a passkey ran", f -> f.authNotes.put(PasskeyAuthenticator.KIND_NOTE, "passkey_synced"));
        cases.put("a certificate ran", f -> f.authNotes.put(X509Authenticator.METHOD_NOTE, "yubikey_cert"));
        cases.put("a password ran", f -> f.authNotes.put(PasswordForm.METHOD_NOTE, "password"));
        cases.forEach((what, setup) -> {
            Flow f = aliceFlow("portcullis-forward-auth");
            Imp.Ops ops = new Imp.Ops(Imp.alice(f, f.person("u-alice", "alice"), "hwk"));
            setup.accept(f);
            assertEquals(ImpersonationGuard.Verdict.REFUSE, check(f, LIVE, ops, ImpersonationGuard.Stage.COOKIE).verdict(), what);
            assertTrue(ops.loggedOut.isEmpty(), what);
        });
    }

    @Test
    void templateStageNeedsTheCookieAlone() {
        // auth-cookie signed in (its note) as alice, nothing else ran: ALLOW.
        Flow f = aliceFlow("nextcloud");
        Flow.Person alice = f.person("u-alice", "alice");
        Imp.Ops ops = new Imp.Ops(Imp.alice(f, alice, "hwk"));
        f.user = alice.model;
        f.completed("hwk");
        f.authNotes.put(CookieAuthenticator.SSO_NOTE, "true");
        assertEquals(ImpersonationGuard.Verdict.ALLOW, check(f, LIVE, ops, ImpersonationGuard.Stage.TEMPLATE).verdict());

        // The cookie didn't sign in (prompt=login skipped it): REFUSE.
        f.authNotes.remove(CookieAuthenticator.SSO_NOTE);
        assertEquals(ImpersonationGuard.Verdict.REFUSE, check(f, LIVE, ops, ImpersonationGuard.Stage.TEMPLATE).verdict());
        f.authNotes.put(CookieAuthenticator.SSO_NOTE, "true");

        // Another account signed in on top of the impersonated cookie: REFUSE.
        Flow.Person root = f.person("u-root", "root");
        f.user = root.model;
        assertEquals(ImpersonationGuard.Verdict.REFUSE, check(f, LIVE, ops, ImpersonationGuard.Stage.TEMPLATE).verdict());
        f.user = alice.model;

        // A method execution beyond the session's (any authenticator, notes or not): REFUSE.
        f.userSessionNotes.put(org.keycloak.models.Constants.AUTHENTICATORS_COMPLETED, f.completedNote("hwk", "pwd"));
        assertEquals(ImpersonationGuard.Verdict.REFUSE, check(f, LIVE, ops, ImpersonationGuard.Stage.TEMPLATE).verdict());
    }

    @Test
    void templateStageSeesTheFlowsUserSession() {
        // The cookie isn't impersonated but the authentication's user session is: never NOT_IMPERSONATED.
        Flow f = aliceFlow("nextcloud");
        Flow.Person alice = f.person("u-alice", "alice");
        Imp.alice(f, alice, "hwk");
        f.user = alice.model;
        f.authNotes.put(CookieAuthenticator.SSO_NOTE, "true");
        ImpersonationGuard.Result r = check(f, ImpersonationFile.DENY, new Imp.Ops(null), ImpersonationGuard.Stage.TEMPLATE);
        assertEquals(ImpersonationGuard.Verdict.ENDED, r.verdict());
    }

    @Test
    void pagesForceChallenge() {
        // REFUSE (either step): the refused page with the banner and Stop, via forceChallenge.
        for (ImpersonationGuard.Stage stage : ImpersonationGuard.Stage.values()) {
            Flow f = aliceFlow("account-console");
            Flow.Person alice = f.person("u-alice", "alice");
            f.user = alice.model;
            f.authNotes.put(CookieAuthenticator.SSO_NOTE, "true");
            Imp.Ops ops = new Imp.Ops(Imp.alice(f, alice, "hwk"));
            ImpersonationGuard.Result r = check(f, LIVE, ops, stage);
            assertEquals(ImpersonationGuard.Verdict.REFUSE, r.verdict());
            ImpersonationGuard.answer(f.context, r, k -> "https://people.example.com/signin", Imp.NOW, ops, stage);
            // auth-cookie is an ALTERNATIVE: a plain challenge would let the next alternative run.
            assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
            assertEquals(ImpersonationResource.PAGE, f.page);
            ImpersonatingPage page = (ImpersonatingPage) f.formAttributes.get(ImpersonationResource.ATTRIBUTE);
            assertEquals(ImpersonatingPage.REFUSED, page.getMode());
            assertEquals("alice", page.getPerson());
            assertFalse(page.isStart());
            assertEquals("https://people.example.com/impersonation/stop", page.getStopUrl());
            ImpersonationBanner banner = (ImpersonationBanner) f.formAttributes.get(ImpersonationResource.BANNER);
            assertEquals("root", banner.getAdmin());
            assertEquals(Imp.REASON, banner.getReason());
        }
    }

    /**
     * After Stop (e2e): at the cookie step an ENDED session is logged out and
     * the same authorize starts again without it — the normal sign-in page,
     * never the ended page, never a sign-in as the person.
     */
    @Test
    void endedAtCookieStepRestartsTheAuthorize() {
        Flow f = aliceFlow("portcullis-forward-auth");
        UserSessionModel us = Imp.alice(f, f.person("u-alice", "alice"), "hwk");
        Imp.Ops ops = new Imp.Ops(us);
        ImpersonationGuard.Result r = check(f, ImpersonationFile.DENY, ops, ImpersonationGuard.Stage.COOKIE);
        assertEquals(ImpersonationGuard.Verdict.ENDED, r.verdict());
        ImpersonationGuard.answer(f.context, r, k -> "https://people.example.com/signin", Imp.NOW, ops, ImpersonationGuard.Stage.COOKIE);
        assertEquals(List.of(us.getId()), ops.loggedOut);
        assertEquals(List.of(f.requestUri), ops.restarted, "the same authorize, again");
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        assertNull(f.page, "no ended page");
        assertNull(f.user);

        // Not the authorize request (a later form post): the ended page with Sign in again instead.
        Flow g = aliceFlow("portcullis-forward-auth");
        g.requestUri = Flow.BASE.resolve("realms/portcullis/login-actions/authenticate?session_code=x&tab_id=t");
        Imp.Ops o2 = new Imp.Ops(Imp.alice(g, g.person("u-alice", "alice"), "hwk"));
        ImpersonationGuard.Result e = check(g, ImpersonationFile.DENY, o2, ImpersonationGuard.Stage.COOKIE);
        ImpersonationGuard.answer(g.context, e, k -> null, Imp.NOW, o2, ImpersonationGuard.Stage.COOKIE);
        assertTrue(o2.restarted.isEmpty());
        assertEquals(ImpersonatingPage.ENDED, ((ImpersonatingPage) g.formAttributes.get(ImpersonationResource.ATTRIBUTE)).getMode());
    }

    /** At the template step the flow can't step aside: the ended page, Sign in again (the authorize again), no Stop, no Try another way. */
    @Test
    void endedAtTemplateStepSignInAgain() {
        Flow f = aliceFlow("nextcloud");
        Flow.Person alice = f.person("u-alice", "alice");
        f.user = alice.model;
        Imp.Ops ops = new Imp.Ops(Imp.alice(f, alice, "hwk"));
        ImpersonationGuard.Result r = check(f, ImpersonationFile.DENY, ops, ImpersonationGuard.Stage.TEMPLATE);
        assertEquals(ImpersonationGuard.Verdict.ENDED, r.verdict());
        ImpersonationGuard.answer(f.context, r, k -> "https://people.example.com/signin", Imp.NOW, ops, ImpersonationGuard.Stage.TEMPLATE);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        assertEquals(ImpersonationResource.PAGE, f.page);
        assertTrue(ops.restarted.isEmpty());
        ImpersonatingPage page = (ImpersonatingPage) f.formAttributes.get(ImpersonationResource.ATTRIBUTE);
        assertEquals(ImpersonatingPage.ENDED, page.getMode());
        assertEquals(f.requestUri.toString(), page.getSignInAgainUrl());
        assertNull(page.getStopUrl(), "no Stop: it has ended");
        assertNull(f.formAttributes.get(ImpersonationResource.BANNER));
        assertTrue(f.selectionsCleared, "no Try another way");

        // A later request (not the authorize): Keycloak's restart of this client's authentication.
        Flow g = aliceFlow("nextcloud");
        g.requestUri = Flow.BASE.resolve("realms/portcullis/login-actions/authenticate?session_code=x");
        Flow.Person a2 = g.person("u-alice", "alice");
        g.user = a2.model;
        Imp.Ops o2 = new Imp.Ops(Imp.alice(g, a2, "hwk"));
        ImpersonationGuard.answer(g.context, check(g, ImpersonationFile.DENY, o2, ImpersonationGuard.Stage.TEMPLATE), k -> null,
                Imp.NOW, o2, ImpersonationGuard.Stage.TEMPLATE);
        String again = ((ImpersonatingPage) g.formAttributes.get(ImpersonationResource.ATTRIBUTE)).getSignInAgainUrl();
        assertTrue(again.startsWith("https://auth.example.com/realms/portcullis/login-actions/restart?client_id=nextcloud"), again);
    }

    @Test
    void neverLogsTheReason() {
        Flow f = aliceFlow("account-console");
        Imp.Ops ops = new Imp.Ops(Imp.alice(f, f.person("u-alice", "alice"), "hwk"));
        List<String> lines = ImpersonationResourceTest.captured(ImpersonationGuard.class, () -> {
            ImpersonationGuard.Result r = check(f, LIVE, ops, ImpersonationGuard.Stage.COOKIE);
            ImpersonationGuard.answer(f.context, r, k -> null, Imp.NOW, ops, ImpersonationGuard.Stage.COOKIE);
            ImpersonationGuard.Result e = check(f, ImpersonationFile.DENY, ops, ImpersonationGuard.Stage.COOKIE);
            ImpersonationGuard.answer(f.context, e, k -> null, Imp.NOW, ops, ImpersonationGuard.Stage.COOKIE);
        });
        assertFalse(lines.isEmpty());
        for (String l : lines) {
            assertFalse(l.contains(Imp.REASON), l);
        }
    }

    @Test
    void impersonatedFromAuthSession() {
        Flow f = new Flow();
        Flow.Person alice = f.person("u-alice", "alice");
        UserSessionModel imp = Imp.alice(f, alice, "hwk");
        // The identity cookie's session.
        Optional<Impersonation.Info> i = ImpersonationGuard.impersonated(f.session, f.realm, f.authSession,
                (s, r) -> new AuthenticationManager.AuthResult(alice.model, imp, null, null));
        assertEquals(Imp.ID, i.orElseThrow().id());
        assertEquals("root", i.get().admin());
        // Or the authentication's own user session (the cookie gone).
        f.user = alice.model;
        assertTrue(ImpersonationGuard.impersonated(f.session, f.realm, f.authSession, (s, r) -> null).isPresent());
        // Partial notes still count as impersonated (refused, never allowed).
        Map<String, String> notes = Imp.notes(f, Imp.ID, Imp.NOW.plusSeconds(60), "hwk");
        notes.remove(Impersonation.ADMIN);
        UserSessionModel partial = Imp.session(f, alice, "us-partial", notes);
        assertTrue(ImpersonationGuard.impersonated(f.session, f.realm, f.authSession,
                (s, r) -> new AuthenticationManager.AuthResult(alice.model, partial, null, null)).isPresent());

        // Not impersonated: empty.
        Flow g = new Flow();
        Flow.Person bob = g.person("u-bob", "bob");
        UserSessionModel plain = g.userSession(bob, "hwk");
        g.user = bob.model;
        assertTrue(ImpersonationGuard.impersonated(g.session, g.realm, g.authSession,
                (s, r) -> new AuthenticationManager.AuthResult(bob.model, plain, null, null)).isEmpty());
        assertTrue(ImpersonationGuard.impersonated(g.session, g.realm, g.authSession, (s, r) -> null).isEmpty());
        assertTrue(ImpersonationGuard.impersonated(null, g.realm, g.authSession, (s, r) -> null).isEmpty());
    }
}
