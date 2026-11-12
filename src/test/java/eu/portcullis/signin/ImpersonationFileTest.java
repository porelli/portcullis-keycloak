package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** {@code hub_data/impersonation.json} (contract §8.1 "Impersonation", D37) and the live check. */
class ImpersonationFileTest {
    static final String ID = "0f3c0000000000000000000000000001";
    static final String OLD = "9a1d0000000000000000000000000002";

    /** The contract's example, with full ids. */
    static String example(String sessionEnded) {
        return """
            {"version": 1, "allowed": true, "written": "2026-11-12T14:03:10Z",
             "clients": ["portcullis-forward-auth", "nextcloud", "nextcloud-office"],
             "pending": [{"id": "%1$s", "admin": "root", "admin_sid": "f7c1e2d4-1b2a-4c3d-9e8f-001122334455", "target": "alice",
                          "reason": "checking quota", "fresh": "security_key", "fresh_at": "2026-11-12T14:02:51Z",
                          "created": "2026-11-12T14:02:58Z", "until": "2026-11-12T14:32:58Z"}],
             "sessions": [{"id": "%1$s", "admin": "root", "target": "alice", "reason": "checking quota",
                           "started": "2026-11-12T14:02:58Z", "until": "2026-11-12T14:32:58Z", "ended": %3$s}],
             "notices": {"bob": [{"id": "%2$s", "admin": "root", "started": "2026-11-10T09:00:00Z", "ended": "2026-11-10T09:12:00Z",
                                  "reason": "fixing the calendar", "apps": [{"name": "Gitea", "own_session": false},
                                                                           {"name": "Nextcloud", "own_session": true}]}]}}
            """.formatted(ID, OLD, sessionEnded);
    }

    static ImpersonationFile parse(String s) throws IOException {
        return ImpersonationFile.parse(s.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void parsesShape() throws Exception {
        ImpersonationFile f = parse(example("null"));
        assertTrue(f.allowed());
        assertEquals(Set.of("portcullis-forward-auth", "nextcloud", "nextcloud-office"), f.clients());
        ImpersonationFile.Pending p = f.pending(ID).orElseThrow();
        assertEquals("root", p.admin());
        assertEquals("f7c1e2d4-1b2a-4c3d-9e8f-001122334455", p.adminSid());
        assertEquals("alice", p.target());
        assertEquals("checking quota", p.reason());
        assertEquals("security_key", p.fresh());
        assertEquals(Instant.parse("2026-11-12T14:02:51Z"), p.freshAt());
        assertEquals(Instant.parse("2026-11-12T14:02:58Z"), p.created());
        assertEquals(Instant.parse("2026-11-12T14:32:58Z"), p.until());
        ImpersonationFile.SessionRec s = f.session(ID).orElseThrow();
        assertEquals("root", s.admin());
        assertEquals("alice", s.target());
        assertEquals(Instant.parse("2026-11-12T14:02:58Z"), s.started());
        assertEquals(null, s.ended());
        List<ImpersonationFile.Notice> n = f.notices("bob");
        assertEquals(1, n.size());
        assertEquals(OLD, n.get(0).id());
        assertEquals(Instant.parse("2026-11-10T09:12:00Z"), n.get(0).ended());
        assertEquals("fixing the calendar", n.get(0).reason());
        assertEquals(List.of(new ImpersonationFile.App("Gitea", false), new ImpersonationFile.App("Nextcloud", true)), n.get(0).apps());
        assertEquals(List.of(), f.notices("alice"));
        assertTrue(f.pending(OLD).isEmpty());
        assertTrue(f.session(OLD).isEmpty());
        assertEquals(Set.of("alice"), f.targets());

        ImpersonationFile ended = parse(example("\"2026-11-12T14:20:00Z\""));
        assertEquals(Instant.parse("2026-11-12T14:20:00Z"), ended.session(ID).orElseThrow().ended());

        ImpersonationFile empty = parse("""
            {"version": 1, "allowed": false, "written": "2026-11-12T14:03:10Z", "clients": [], "pending": [], "sessions": [], "notices": {}}""");
        assertFalse(empty.allowed());
        assertTrue(empty.targets().isEmpty());
    }

    @Test
    void invalidIsDeny(@TempDir Path dir) throws Exception {
        // missing file
        assertSame(ImpersonationFile.DENY, ImpersonationFile.load(dir.resolve("impersonation.json")));
        assertFalse(ImpersonationFile.DENY.allowed());
        assertTrue(ImpersonationFile.DENY.clients().isEmpty());
        assertTrue(ImpersonationFile.DENY.pending(ID).isEmpty());
        assertTrue(ImpersonationFile.DENY.session(ID).isEmpty());
        assertTrue(ImpersonationFile.DENY.targets().isEmpty());

        String good = example("null");
        List<String> bad = List.of(
                "{",                                                           // bad JSON
                good + "{}",                                                   // trailing data
                good.replace("\"version\": 1", "\"version\": 2"),              // another version
                good.replace("\"allowed\": true", "\"allowed\": true, \"extra\": 1"), // unknown field
                good.replace("\"own_session\": false", "\"own_session\": false, \"x\": 1"),
                good.replace(ID, "ABC"),                                       // an id outside ^[0-9a-f]{32}$
                good.replace(ID, ID.toUpperCase()),
                good.replace("\"reason\": \"checking quota\", \"fresh\"", "\"reason\": \"checking\\u0007quota\", \"fresh\""), // a control character
                good.replace("\"reason\": \"checking quota\", \"fresh\"", "\"reason\": \"ab\", \"fresh\""),     // under 3
                good.replace("\"reason\": \"checking quota\", \"fresh\"", "\"reason\": \"" + "x".repeat(201) + "\", \"fresh\""),
                good.replace("\"reason\": \"checking quota\", \"fresh\"", "\"reason\": \"check\\u202equota\", \"fresh\""), // bidi
                good.replace("\"reason\": \"checking quota\", \"fresh\"", "\"reason\": \"line\\nbreak\", \"fresh\""),
                good.replace("\"admin\": \"root\", \"admin_sid\"", "\"admin\": \"Root\", \"admin_sid\""), // a username outside the rule
                good.replaceFirst("\"target\": \"alice\"", "\"target\": \"-alice\""),
                good.replace("\"fresh\": \"security_key\"", "\"fresh\": \"password\""),   // not a touch
                good.replace("\"fresh_at\": \"2026-11-12T14:02:51Z\"", "\"fresh_at\": \"yesterday\""), // a bad time
                good.replace("\"ended\": null", "\"ended\": 5"),
                good.replace("\"ended\": null", ""),                         // missing field (with the comma left: bad JSON too)
                good.replace(", \"ended\": null", ""),                       // missing field
                good.replace("\"admin_sid\": \"f7c1e2d4-1b2a-4c3d-9e8f-001122334455\"", "\"admin_sid\": null"),
                good.replace("\"admin_sid\": \"f7c1e2d4-1b2a-4c3d-9e8f-001122334455\"", "\"admin_sid\": \"\""),
                good.replace("\"allowed\": true", "\"allowed\": \"true\""),  // a coerced scalar
                good.replace("\"nextcloud-office\"", "\"nextcloud-office\", \"\""),
                good.replace("\"bob\": [", "\"Bob!\": ["),
                good.replace("\"name\": \"Gitea\"", "\"name\": \"\""),
                good.replace("\"sessions\": [{", "\"sessions\": [{\"id\": \"" + ID + "\", \"admin\": \"root\", \"target\": \"alice\", \"reason\": \"checking quota\", \"started\": \"2026-11-12T14:02:58Z\", \"until\": \"2026-11-12T14:32:58Z\", \"ended\": null}, {")); // an id twice
        for (String b : bad) {
            assertThrows(Exception.class, () -> parse(b), b);
            Path p = dir.resolve("impersonation.json");
            Files.writeString(p, b);
            assertSame(ImpersonationFile.DENY, ImpersonationFile.load(p), b);
        }
        Path p = dir.resolve("impersonation.json");
        Files.writeString(p, good);
        assertTrue(ImpersonationFile.load(p).allowed());
    }

    @Test
    void cachedByStamp(@TempDir Path dir) throws Exception {
        Path p = dir.resolve("impersonation.json");
        ImpersonationFile.Cache c = new ImpersonationFile.Cache(p);
        assertSame(ImpersonationFile.DENY, c.get());
        Files.writeString(p, example("null"));
        ImpersonationFile first = c.get();
        assertTrue(first.allowed());
        assertSame(first, c.get(), "unchanged: the cached file");
        Files.writeString(p, "{not json, and a different size}");
        assertSame(ImpersonationFile.DENY, c.get());
    }

    // ── Impersonation.live ──

    static final Instant NOW = Instant.parse("2026-11-12T14:10:00Z");
    static final Instant UNTIL = Instant.parse("2026-11-12T14:32:58Z");

    @Test
    void liveNeedsEverything() throws Exception {
        ImpersonationFile f = parse(example("null"));
        Impersonation.Info i = new Impersonation.Info(ID, "root", "checking quota", UNTIL);
        assertTrue(Impersonation.live(i, "alice", f, NOW));

        // ended set
        assertFalse(Impersonation.live(i, "alice", parse(example("\"2026-11-12T14:05:00Z\"")), NOW));
        // admin differs / target differs
        assertFalse(Impersonation.live(new Impersonation.Info(ID, "sam", "checking quota", UNTIL), "alice", f, NOW));
        assertFalse(Impersonation.live(i, "bob", f, NOW));
        // now ≥ until: the note's, or the record's
        assertFalse(Impersonation.live(i, "alice", f, UNTIL));
        assertFalse(Impersonation.live(new Impersonation.Info(ID, "root", "checking quota", NOW), "alice", f, NOW));
        assertFalse(Impersonation.live(new Impersonation.Info(ID, "root", "checking quota", UNTIL.plusSeconds(600)), "alice", f,
                UNTIL.plusSeconds(1)));
        // allowed false
        assertFalse(Impersonation.live(i, "alice", parse(example("null").replace("\"allowed\": true", "\"allowed\": false")), NOW));
        assertFalse(Impersonation.live(i, "alice", ImpersonationFile.DENY, NOW));
        // an unknown id; partial notes (id only)
        assertFalse(Impersonation.live(new Impersonation.Info(OLD, "root", "checking quota", UNTIL), "alice", f, NOW));
        assertFalse(Impersonation.live(new Impersonation.Info(ID, null, null, null), "alice", f, NOW));
        assertFalse(Impersonation.live(null, "alice", f, NOW));
    }

    @Test
    void infoFromNotes() {
        Flow flow = new Flow();
        java.util.Map<String, String> notes = new java.util.HashMap<>();
        org.keycloak.models.UserSessionModel us = Fake.named("us").on("getNote", a -> notes.get((String) a[0]))
                .as(org.keycloak.models.UserSessionModel.class);
        assertTrue(Impersonation.of(us).isEmpty());
        assertTrue(Impersonation.of(null).isEmpty());
        notes.put(Impersonation.ID, ID);
        assertEquals(new Impersonation.Info(ID, null, null, null), Impersonation.of(us).orElseThrow(), "partial: id only");
        notes.put("IMPERSONATOR_USERNAME", "root");
        notes.put(Impersonation.REASON, "checking quota");
        notes.put(Impersonation.UNTIL, "not a number");
        assertEquals(new Impersonation.Info(ID, null, null, null), Impersonation.of(us).orElseThrow(), "a bad until: id only");
        notes.put(Impersonation.UNTIL, String.valueOf(UNTIL.getEpochSecond()));
        assertEquals(new Impersonation.Info(ID, "root", "checking quota", UNTIL), Impersonation.of(us).orElseThrow());
        assertTrue(flow.users.isEmpty());
    }
}
