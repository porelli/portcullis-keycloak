package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** The method table (contract §8.1 "Methods"): the seven ids, their amr values and strengths. */
class MethodsTest {
    @Test
    void sevenIdsInCanonicalOrder() {
        assertEquals(List.of("password", "totp", "passkey_synced", "browser_cert", "passkey_device", "security_key", "yubikey_cert"),
                Methods.IDS);
        assertTrue(Methods.known("totp"));
        assertFalse(Methods.known("otp"));
        assertEquals(1, Methods.rank("totp"));
        assertFalse(Methods.PASSKEY_KINDS.contains("totp"));
    }

    @Test
    void totpRow() {
        assertEquals(Optional.of("totp"), Methods.forAmr("otp"));
        assertEquals("otp", Methods.amrOf("totp"));
        assertEquals(15, Methods.tenths("totp"));
        // Between a password and a synced passkey.
        assertTrue(Methods.tenths("password") < Methods.tenths("totp"));
        assertTrue(Methods.tenths("totp") < Methods.tenths("passkey_synced"));
    }

    /** The Hub's methodSet is a uint8: one bit per method, so at most 8. */
    @Test
    void fitsInEightBits() {
        assertTrue(Methods.IDS.size() <= 8, "Rule's method masks and the Hub's methodSet hold 8 methods: widen them first");
    }
}
