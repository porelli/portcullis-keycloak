package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The event details the Hub's history reads (contract §8.1 "History details"). */
class HistoryTest {
    @Test
    void kinds() {
        assertEquals("sso", History.kind(true, Set.of()));
        assertEquals("step_up", History.kind(true, Set.of("security_key")));
        assertEquals("sign_in", History.kind(false, Set.of("security_key")));
        assertEquals("sign_in", History.kind(false, Set.of()));
    }

    @Test
    void successDetailsInTableOrder() {
        Flow f = new Flow();
        f.headers.put("user-agent", "UA\u0007");
        f.event.detail(History.METHOD, "password");
        Set<String> thisAuth = new LinkedHashSet<>(List.of("yubikey_cert", "password"));
        History.onSuccess(f.context, thisAuth, Set.of("security_key", "yubikey_cert", "password"), "step_up");
        Map<String, String> d = f.eventDetails();
        assertEquals("step_up", d.get(History.KIND));
        assertEquals("password,yubikey_cert", d.get(History.METHODS));
        assertEquals("password,security_key,yubikey_cert", d.get(History.SESSION));
        assertEquals("UA", d.get(History.UA));
        assertFalse(d.containsKey(History.METHOD));
    }

    @Test
    void failureDetails() {
        Flow f = new Flow();
        History.onFailure(f.context, "browser_cert");
        assertEquals("browser_cert", f.eventDetails().get(History.METHOD));
        assertEquals("", f.eventDetails().get(History.UA));
        History.onFailure(f.context, "security_key"); // the newest try wins
        assertEquals("security_key", f.eventDetails().get(History.METHOD));
    }

    /**
     * A LOGIN after a required action is sent in a later request with that
     * request's builder: onSuccess keeps its details in authentication notes
     * and reapply puts them on another builder, empty values included.
     */
    @Test
    void successDetailsReappliedOnALaterBuilder() {
        Flow f = new Flow();
        f.headers.put("user-agent", "UA");
        History.onSuccess(f.context, Set.of(), Set.of("security_key"), "sso");
        assertEquals("sso", f.authNotes.get(History.NOTE_PREFIX + History.KIND));
        assertEquals("", f.authNotes.get(History.NOTE_PREFIX + History.METHODS));

        Flow later = new Flow(); // the required action's request: a fresh builder
        later.event.detail(History.METHOD, "password");
        History.reapply(f.authSession, later.event);
        Map<String, String> d = later.eventDetails();
        assertEquals("sso", d.get(History.KIND));
        assertEquals("", d.get(History.METHODS));
        assertEquals("security_key", d.get(History.SESSION));
        assertEquals("UA", d.get(History.UA));
        assertFalse(d.containsKey(History.METHOD));
        assertEquals(f.eventDetails(), d);
    }

    @Test
    void nothingReappliedWithoutTheTemplatesNotes() {
        Flow f = new Flow();
        Flow later = new Flow();
        History.reapply(f.authSession, later.event);
        assertFalse(later.eventDetails().containsKey(History.KIND));
    }
    /**
     * F24: a LOGIN in an impersonated session (the authentication's user
     * session has Portcullis' notes) carries pc_act = the administrator, and
     * the re-apply after a required action carries it too; a session that
     * isn't impersonated never has it.
     */
    @Test
    void actWhenImpersonated() {
        Flow f = new Flow();
        Flow.Person alice = f.person("u-alice", "alice");
        f.user = alice.model;
        Map<String, String> notes = new java.util.HashMap<>(Map.of(Impersonation.ID, ImpersonationFileTest.ID,
                "IMPERSONATOR_USERNAME", "root", Impersonation.UNTIL, "1794494578", Impersonation.REASON, "checking quota"));
        f.userSessions.put(f.rootId, Fake.named("alice session").ret("getId", f.rootId).ret("getUser", alice.model)
                .on("getNote", a -> notes.get((String) a[0])).as(org.keycloak.models.UserSessionModel.class));
        History.onSuccess(f.context, Set.of(), Set.of("security_key"), "sso");
        assertEquals("root", f.eventDetails().get(History.ACT));
        assertTrue(History.SUCCESS_DETAILS.contains(History.ACT));
        assertFalse(f.eventDetails().toString().contains("quota"));

        Flow later = new Flow();
        History.reapply(f.authSession, later.event);
        assertEquals("root", later.eventDetails().get(History.ACT));

        // Not impersonated: no pc_act, on the event or after a re-apply.
        Flow plain = new Flow();
        plain.user = plain.person("u-alice", "alice").model;
        History.onSuccess(plain.context, Set.of(), Set.of("security_key"), "sso");
        assertFalse(plain.eventDetails().containsKey(History.ACT));
        Flow plainLater = new Flow();
        History.reapply(plain.authSession, plainLater.event);
        assertFalse(plainLater.eventDetails().containsKey(History.ACT));
        assertEquals("sso", plainLater.eventDetails().get(History.KIND));

        // The stock feature's notes alone aren't an impersonation; a session of someone else isn't this one's.
        Flow stock = new Flow();
        stock.user = stock.person("u-alice", "alice").model;
        stock.userSessions.put(stock.rootId, Fake.named("s").ret("getUser", stock.user)
                .on("getNote", a -> "IMPERSONATOR_USERNAME".equals(a[0]) ? "root" : null).as(org.keycloak.models.UserSessionModel.class));
        History.onSuccess(stock.context, Set.of(), Set.of(), "sso");
        assertFalse(stock.eventDetails().containsKey(History.ACT));
    }
}
