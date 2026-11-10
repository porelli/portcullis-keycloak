package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.Test;

class PcMethodTest {
    @Test
    void ignoresUnknownValues() {
        for (String v : new String[] {"webauthn", "", "Security_Key", "security_key ", "family:passkey", "inv", "hwk", "browser-cert"}) {
            Flow f = new Flow();
            f.clientNotes.put(PcMethod.CLIENT_NOTE, v);
            assertEquals(Optional.empty(), PcMethod.requested(f.context), v);
        }
        assertEquals(Optional.empty(), PcMethod.requested(new Flow().context));
    }

    @Test
    void readsTheSixIdsAndPasskey() {
        for (String v : new String[] {"password", "passkey_synced", "browser_cert", "passkey_device", "security_key", "yubikey_cert", "passkey"}) {
            Flow f = new Flow();
            f.clientNotes.put(PcMethod.CLIENT_NOTE, v);
            assertEquals(Optional.of(v), PcMethod.requested(f.context), v);
        }
    }

    @Test
    void templateStepWinsOverTheClientNote() {
        Flow f = new Flow();
        f.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key");
        f.authNotes.put(PcMethod.STEP_NOTE, "yubikey_cert");
        assertEquals(Optional.of("yubikey_cert"), PcMethod.requested(f.context));
        f.authNotes.put(PcMethod.STEP_NOTE, "bogus");
        assertEquals(Optional.of("security_key"), PcMethod.requested(f.context));
    }

    @Test
    void allowsAndMet() {
        assertTrue(PcMethod.allows(Optional.empty(), "password"));
        assertTrue(PcMethod.allows(Optional.of("passkey"), "passkey_device"));
        assertFalse(PcMethod.allows(Optional.of("passkey"), "yubikey_cert"));
        assertFalse(PcMethod.allows(Optional.of("security_key"), "passkey_synced"));
        assertTrue(PcMethod.metBy("passkey", java.util.Set.of("passkey_synced")));
        assertFalse(PcMethod.metBy("passkey", java.util.Set.of("yubikey_cert")));
        assertFalse(PcMethod.metBy("security_key", java.util.Set.of("passkey_synced")));
    }
}
