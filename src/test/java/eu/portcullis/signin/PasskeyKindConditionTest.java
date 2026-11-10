package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class PasskeyKindConditionTest {
    private static boolean match(String configured, String used) {
        Flow f = new Flow();
        if (configured != null) {
            f.config(Map.of("kind", configured));
        }
        if (used != null) {
            f.authNotes.put(PasskeyAuthenticator.KIND_NOTE, used);
        }
        return PasskeyKindCondition.SINGLETON.matchCondition(f.context);
    }

    @Test
    void matchesTheKindUsed() {
        assertTrue(match("security_key", "security_key"));
        assertFalse(match("security_key", "passkey_synced"));
        assertFalse(match("security_key", null));
        assertFalse(match(null, "security_key"));
        assertFalse(match("yubikey_cert", "yubikey_cert"), "not a passkey kind");
        assertFalse(match("webauthn", "webauthn"));
    }
}
