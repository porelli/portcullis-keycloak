package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Errors;

class PasswordFormTest {
    private static final SigninConfig ON = Configs.of(Configs.WITH_PASSWORD, false, "", "");
    private static final String RIGHT = "correct horse battery staple";

    @Test
    void skippedWhenOffOrOtherMethodRequested() {
        Flow off = new Flow();
        new PasswordForm(Configs::plain).authenticate(off.context); // password off
        assertEquals(FlowStatus.ATTEMPTED, off.status);
        assertNull(off.page);

        Flow other = new Flow();
        other.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key");
        new PasswordForm(() -> ON).authenticate(other.context);
        assertEquals(FlowStatus.ATTEMPTED, other.status);

        Flow passkey = new Flow();
        passkey.clientNotes.put(PcMethod.CLIENT_NOTE, "passkey");
        new PasswordForm(() -> ON).authenticate(passkey.context);
        assertEquals(FlowStatus.ATTEMPTED, passkey.status);

        Flow asked = new Flow();
        asked.clientNotes.put(PcMethod.CLIENT_NOTE, "password");
        new PasswordForm(() -> ON).authenticate(asked.context);
        assertEquals(FlowStatus.CHALLENGE, asked.status);
        assertEquals("login", asked.page);

        Flow posted = new Flow(); // a form posted after password was switched off
        posted.person("u-alice", "alice").password = RIGHT;
        posted.form.putSingle("username", "alice");
        posted.form.putSingle("password", RIGHT);
        new PasswordForm(Configs::plain).action(posted.context);
        assertEquals(FlowStatus.FAILED, posted.status);
        assertEquals(AuthenticationFlowError.ACCESS_DENIED, posted.error);
    }

    private static Flow login(String typed) {
        Flow f = new Flow();
        f.person("u-admin", "admin").password = RIGHT;
        f.person("u-hub", "portcullis-hub").password = RIGHT;
        f.person("u-alice", "alice").password = RIGHT;
        f.emails.put("root@example.com", f.users.get("admin"));
        f.form.putSingle("username", typed);
        f.form.putSingle("password", RIGHT);
        new PasswordForm(() -> ON).action(f.context);
        return f;
    }

    @Test
    void refusesAdminAndHubAccount() {
        for (String typed : new String[] {"admin", "Admin", " ADMIN ", "portcullis-hub", "Portcullis-Hub", "root@example.com"}) {
            Flow f = login(typed);
            // The form again with the message; brute-force protection counts nothing
            // (no password was checked), so nobody can lock these accounts out.
            assertEquals(FlowStatus.FORCE_CHALLENGE, f.status, typed);
            assertFalse(f.countedByBruteForce(), typed);
            assertEquals("login", f.page, typed);
            assertEquals(typed.trim(), f.authNotes.get(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME), typed);
            assertEquals(java.util.List.of(Errors.INVALID_USER_CREDENTIALS), f.eventErrors, typed);
            assertEquals(java.util.List.of(PasswordForm.REFUSED), f.formErrorsOrFieldErrors(), typed);
            assertNull(f.user, typed);
            assertNull(f.authNotes.get(PasswordForm.METHOD_NOTE), typed + ": no password sign-in, no pc_fresh");
            for (Flow.Person p : f.people()) {
                assertTrue(p.checked.isEmpty(), typed + ": the password is never checked");
            }
        }
        Flow alice = login("alice");
        assertEquals(FlowStatus.SUCCESS, alice.status);
        assertEquals("password", alice.authNotes.get(PasswordForm.METHOD_NOTE));
        Flow wrong = new Flow(); // a wrong password, for comparison, is counted
        wrong.person("u-alice", "alice").password = RIGHT;
        wrong.form.putSingle("username", "alice");
        wrong.form.putSingle("password", "nope");
        new PasswordForm(() -> ON).action(wrong.context);
        assertTrue(wrong.countedByBruteForce());
        assertNull(wrong.authNotes.get(PasswordForm.METHOD_NOTE));
        assertSame(alice.users.get("alice"), alice.user);
    }

    @Test
    void refusesAKnownAdminWithoutAForm() {
        Flow f = new Flow();
        f.user = f.person("u-admin", "admin").model; // e.g. a step-up that asked for a password
        f.clientNotes.put(PcMethod.CLIENT_NOTE, "password");
        new PasswordForm(() -> ON).authenticate(f.context);
        assertEquals(FlowStatus.ATTEMPTED, f.status);
    }
}
