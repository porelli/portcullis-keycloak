package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class PasskeyRegisterTest {
    private static final SigninConfig OFF = Fixtures.config(1, false);
    private static final SigninConfig ON = Fixtures.config(1, true);

    @Test
    void strongerFromWeakerRefusedWhenOff() {
        PasskeyRegister.Cap c = PasskeyRegister.cap(Set.of("spk"), "security_key", false, OFF);
        assertFalse(c.allowed());
        assertFalse(PasskeyRegister.cap(Set.of("spk"), "passkey_device", false, OFF).allowed());
        // Equal or weaker: allowed, capped at the session's kind.
        assertEquals(new PasskeyRegister.Cap(true, "passkey_synced"), PasskeyRegister.cap(Set.of("spk"), "passkey_synced", false, OFF));
        assertEquals(new PasskeyRegister.Cap(true, "passkey_device"), PasskeyRegister.cap(Set.of("dpk"), "passkey_synced", false, OFF));
        assertEquals(new PasskeyRegister.Cap(true, "security_key"), PasskeyRegister.cap(Set.of("spk", "mtls"), "security_key", false, OFF));
        // A password alone registers nothing; a switched-off method counts as nothing.
        assertFalse(PasskeyRegister.cap(Set.of("pwd"), "passkey_synced", false, OFF).allowed());
        assertFalse(PasskeyRegister.cap(Set.of(), "passkey_synced", false, OFF).allowed());
        assertFalse(PasskeyRegister.cap(Set.of("hwk"), "security_key", false, SigninConfig.DENY_ALL).allowed());
        assertFalse(PasskeyRegister.cap(Set.of("hwk"), "webauthn", false, OFF).allowed(), "not a kind");
        // add_stronger on: no cap.
        assertEquals(new PasskeyRegister.Cap(true, null), PasskeyRegister.cap(Set.of("spk"), "security_key", true, ON));
    }

    @Test
    void setupLinkSessionMayAddStronger() {
        PasskeyRegister.Cap c = PasskeyRegister.cap(Set.of("inv"), "security_key", false, OFF);
        assertTrue(c.allowed());
        assertNull(c.cappedAt());
    }

    @Test
    void adminsGetSecurityKeyFirstHints() throws Exception {
        ObjectMapper json = new ObjectMapper();
        String admin = PasskeyRegister.hintsFor(TestDb.user("u1", "root", "people", "lldap_admin"));
        assertEquals(List.of("security-key", "client-device", "hybrid"), json.readValue(admin, List.class));
        String other = PasskeyRegister.hintsFor(TestDb.user("u2", "alice", "people"));
        assertEquals(List.of("client-device", "hybrid", "security-key"), json.readValue(other, List.class));
        assertEquals("[\"security-key\",\"client-device\",\"hybrid\"]", admin);
        assertEquals("[\"client-device\",\"hybrid\",\"security-key\"]", other);
        assertEquals("portcullisHints", PasskeyRegister.HINTS_ATTRIBUTE);
    }
}
