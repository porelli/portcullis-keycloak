package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

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
}
