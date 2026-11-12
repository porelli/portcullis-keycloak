package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import eu.portcullis.signin.store.ImpersonatedStore;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;

/** portcullis-impersonation-expiry (contract §8.1 "Ending", D41): every 15 s, every non-live impersonated session logged out. */
class ImpersonationExpiryTest {
    static final String ENDED = "0f3c0000000000000000000000000003";
    static final String OVERDUE = "0f3c0000000000000000000000000004";

    /** The realm's sessions by username, and the ids logged out. */
    static class Ops implements ImpersonationExpiry.Ops {
        final Flow f = new Flow();
        final Map<String, List<UserSessionModel>> byUser = new HashMap<>();
        final Set<String> loggedOut = new TreeSet<>();
        final List<String> asked = new ArrayList<>();
        /** PORTCULLIS_IMPERSONATED: user id → mark. */
        final Map<String, ImpersonatedStore.Mark> marks = new java.util.TreeMap<>();

        @Override
        public List<RealmModel> realms(KeycloakSession s) {
            return List.of(f.realm);
        }

        @Override
        public List<UserSessionModel> sessions(KeycloakSession s, RealmModel r, String username) {
            asked.add(username);
            return byUser.getOrDefault(username, List.of());
        }

        @Override
        public List<UserSessionModel> sessionsOf(KeycloakSession s, RealmModel r, String userId) {
            asked.add("id:" + userId);
            return byUser.entrySet().stream().filter(e -> ("u-" + e.getKey()).equals(userId))
                    .flatMap(e -> e.getValue().stream()).toList();
        }

        @Override
        public List<ImpersonatedStore.Mark> marked(KeycloakSession s, RealmModel r) {
            return List.copyOf(marks.values());
        }

        @Override
        public void unmark(KeycloakSession s, RealmModel r, String userId, long since) {
            ImpersonatedStore.Mark m = marks.get(userId);
            if (m != null && m.since() <= since) {
                marks.remove(userId);
            }
        }

        @Override
        public void logOut(KeycloakSession s, RealmModel r, UserSessionModel us) {
            loggedOut.add(us.getId());
            byUser.values().forEach(l -> l.removeIf(x -> x.getId().equals(us.getId())));
        }

        void mark(String username, java.time.Instant since) {
            marks.put("u-" + username, new ImpersonatedStore.Mark("u-" + username, username, since.getEpochSecond()));
        }

        UserSessionModel add(String username, String sid, Map<String, String> notes) {
            Flow.Person p = f.people().stream().filter(x -> x.username.equals(username)).findFirst()
                    .orElseGet(() -> f.person("u-" + username, username));
            UserSessionModel us = Imp.session(f, p, sid, notes);
            byUser.computeIfAbsent(username, k -> new ArrayList<>()).add(us);
            return us;
        }
    }

    /** The file: ID running, ENDED ended, OVERDUE running with a past note; all alice's; bob running under OTHER. */
    static ImpersonationFile file() {
        return Imp.file(true, List.of(
                new Imp.Rec(Imp.ID, "alice", Imp.NOW.plusSeconds(1800), "null"),
                new Imp.Rec(ENDED, "alice", Imp.NOW.plusSeconds(1800), "\"" + Imp.NOW.minusSeconds(20) + "\""),
                new Imp.Rec(OVERDUE, "alice", Imp.NOW.plusSeconds(1800), "null"),
                new Imp.Rec(Imp.OTHER, "bob", Imp.NOW.plusSeconds(1800), "null")), "portcullis-forward-auth");
    }

    static Ops sessions() {
        Ops o = new Ops();
        o.add("alice", "s-live", Imp.notes(o.f, Imp.ID, Imp.NOW.plusSeconds(1800), "hwk"));
        o.add("alice", "s-ended", Imp.notes(o.f, ENDED, Imp.NOW.plusSeconds(1800), "hwk"));
        o.add("alice", "s-overdue", Imp.notes(o.f, OVERDUE, Imp.NOW.minusSeconds(1), "hwk"));
        o.add("alice", "s-own", new HashMap<>(Map.of())); // alice's own session: no note, never touched
        o.add("bob", "s-bob", Imp.notes(o.f, Imp.OTHER, Imp.NOW.plusSeconds(1800), "hwk"));
        return o;
    }

    @Test
    void removesEndedAndOverdue() {
        Ops o = sessions();
        Map<String, String> partial = Imp.notes(o.f, Imp.ID, Imp.NOW.plusSeconds(1800), "hwk");
        partial.remove(Impersonation.REASON);
        o.add("alice", "s-partial", partial); // M4: partial notes are never live
        ImpersonationFile f = file();
        ImpersonationExpiry task = new ImpersonationExpiry(() -> f, () -> Imp.NOW, o);
        assertEquals(ImpersonationExpiry.TASK_NAME, task.getTaskName());
        assertEquals(15_000, ImpersonationExpiry.INTERVAL_MS);
        task.run(o.f.session);
        assertEquals(Set.of("s-ended", "s-overdue", "s-partial"), o.loggedOut);
        assertEquals(Set.of("alice", "bob"), Set.copyOf(o.asked), "the file's persons");
    }

    @Test
    void switchedOffEndsEveryOne() {
        Ops o = sessions();
        ImpersonationFile off = Imp.file(false, List.of(new Imp.Rec(Imp.ID, "alice", Imp.NOW.plusSeconds(1800), "null"),
                new Imp.Rec(Imp.OTHER, "bob", Imp.NOW.plusSeconds(1800), "null")));
        new ImpersonationExpiry(() -> off, () -> Imp.NOW, o).run(o.f.session);
        assertEquals(Set.of("s-live", "s-ended", "s-overdue", "s-bob"), o.loggedOut);
    }

    @Test
    void unreadableFileUsesLastTargets() {
        Ops o = sessions();
        ImpersonationFile[] current = {file()};
        ImpersonationExpiry task = new ImpersonationExpiry(() -> current[0], () -> Imp.NOW, o);
        task.run(o.f.session);
        assertEquals(Set.of("s-ended", "s-overdue"), o.loggedOut);
        o.loggedOut.clear();
        current[0] = ImpersonationFile.DENY;
        task.run(o.f.session);
        // Fail closed: every impersonated session left of the last good file's persons ends; alice's own stays.
        assertEquals(Set.of("s-live", "s-bob"), o.loggedOut);
        assertFalse(o.loggedOut.contains("s-own"));

        // Still unreadable on the next run: the same persons are walked again.
        o.asked.clear();
        task.run(o.f.session);
        assertEquals(Set.of("alice", "bob"), Set.copyOf(o.asked));
    }

    @Test
    void neverAGoodFileWalksNobody() {
        Ops o = sessions();
        new ImpersonationExpiry(() -> ImpersonationFile.DENY, () -> Imp.NOW, o).run(o.f.session);
        assertTrue(o.asked.isEmpty());
    }

    @Test
    void oneFailureDoesntStopTheRest() {
        Ops o = new Ops() {
            @Override
            public void logOut(KeycloakSession s, RealmModel r, UserSessionModel us) {
                if (us.getId().equals("s-ended")) {
                    throw new IllegalStateException("boom");
                }
                super.logOut(s, r, us);
            }
        };
        o.add("alice", "s-ended", Imp.notes(o.f, ENDED, Imp.NOW.plusSeconds(1800), "hwk"));
        o.add("alice", "s-overdue", Imp.notes(o.f, OVERDUE, Imp.NOW.minusSeconds(1), "hwk"));
        ImpersonationFile f = file();
        List<String> lines = ImpersonationResourceTest.captured(ImpersonationExpiry.class,
                () -> new ImpersonationExpiry(() -> f, () -> Imp.NOW, o).run(o.f.session));
        assertEquals(Set.of("s-overdue"), o.loggedOut);
        assertFalse(lines.isEmpty());
        for (String l : lines) {
            assertFalse(l.contains(Imp.REASON), l);
        }
    }

    // ── The durable set (PORTCULLIS_IMPERSONATED): restarts, unreadable files, dropped records ──

    /** Keycloak restarted while the file is unreadable: nothing in memory, the table still names alice. */
    @Test
    void restartWithDenyFileStillLogsOut() {
        Ops o = sessions();
        o.mark("alice", Imp.NOW.minusSeconds(600));
        new ImpersonationExpiry(() -> ImpersonationFile.DENY, () -> Imp.NOW, o).run(o.f.session);
        assertEquals(Set.of("s-live", "s-ended", "s-overdue"), o.loggedOut);
        assertFalse(o.marks.containsKey("u-alice"), "no impersonated session left: the mark is removed");
    }

    /** The record dropped from a readable file (here: no records at all) — the mark still finds the session. */
    @Test
    void recordDroppedStillLogsOut() {
        Ops o = sessions();
        o.mark("alice", Imp.NOW.minusSeconds(600));
        ImpersonationFile empty = Imp.file(true, List.of(), "portcullis-forward-auth");
        new ImpersonationExpiry(() -> empty, () -> Imp.NOW, o).run(o.f.session);
        assertEquals(Set.of("s-live", "s-ended", "s-overdue"), o.loggedOut);
        assertTrue(o.marks.isEmpty());
        assertFalse(o.loggedOut.contains("s-own"));
    }

    @Test
    void markKeptWhileLive() {
        Ops o = sessions();
        o.mark("alice", Imp.NOW.minusSeconds(600));
        ImpersonationFile f = file();
        new ImpersonationExpiry(() -> f, () -> Imp.NOW, o).run(o.f.session);
        assertFalse(o.loggedOut.contains("s-live"));
        assertTrue(o.marks.containsKey("u-alice"), "a live impersonated session is left: the mark stays");
    }

    @Test
    void markClearedOnlyWhenNothingLeftAndNotFresh() {
        Ops o = new Ops();
        o.f.person("u-alice", "alice");
        o.mark("alice", Imp.NOW.minusSeconds(600));
        o.mark("carol", Imp.NOW.minusSeconds(10)); // a start racing the task: its session may not be visible yet
        new ImpersonationExpiry(() -> ImpersonationFile.DENY, () -> Imp.NOW, o).run(o.f.session);
        assertEquals(Set.of("u-carol"), o.marks.keySet());

        // A logout that fails keeps the mark (retried next run).
        Ops failing = new Ops() {
            @Override
            public void logOut(KeycloakSession s, RealmModel r, UserSessionModel us) {
                throw new IllegalStateException("boom");
            }
        };
        failing.add("alice", "s-live", Imp.notes(failing.f, Imp.ID, Imp.NOW.plusSeconds(1800), "hwk"));
        failing.mark("alice", Imp.NOW.minusSeconds(600));
        new ImpersonationExpiry(() -> ImpersonationFile.DENY, () -> Imp.NOW, failing).run(failing.f.session);
        assertTrue(failing.marks.containsKey("u-alice"));
    }
}
