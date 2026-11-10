package eu.portcullis.signin;

import static eu.portcullis.signin.Fixtures.BIT_BE;
import static eu.portcullis.signin.Fixtures.BIT_BS;
import static eu.portcullis.signin.Fixtures.BIT_UP;
import static eu.portcullis.signin.Fixtures.BIT_UV;
import static eu.portcullis.signin.Fixtures.OTHER;
import static eu.portcullis.signin.Fixtures.YUBIKEY;
import static eu.portcullis.signin.Fixtures.ZERO;
import static eu.portcullis.signin.Fixtures.config;
import static eu.portcullis.signin.Fixtures.entry;
import static eu.portcullis.signin.Fixtures.root2;
import static eu.portcullis.signin.Fixtures.root3;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.webauthn4j.test.EmulatorUtil;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class PasskeyClassifierTest {
    private static final Instant NOW = Instant.parse("2026-11-10T00:00:00Z");

    private static SigninConfig trusted(java.util.UUID aaguid, String kind, String status) {
        return config(7, false, entry(aaguid, kind, status, root3()));
    }

    @Test
    void packedChainToTrustedRootIsSecurityKey() {
        // A real registration from webauthn4j-test's packed emulator (AAGUID zero, no AAGUID extension).
        StoredAttestation emulated = Fixtures.emulatedPacked();
        assertEquals("packed", emulated.fmt());
        assertEquals(ZERO, emulated.aaguid());
        assertFalse(emulated.backupEligible());
        assertEquals("security_key", PasskeyClassifier.kind(emulated, trusted(ZERO, "security_key", "certified"), NOW));

        // A YubiKey AAGUID with a matching leaf extension.
        StoredAttestation built = Fixtures.packed(YUBIKEY);
        assertEquals("security_key", PasskeyClassifier.kind(built, trusted(YUBIKEY, "security_key", "certified"), NOW));
        // Deterministic.
        assertEquals("security_key", PasskeyClassifier.kind(built, trusted(YUBIKEY, "security_key", "certified"), NOW));
        // The same attestation without that list entry: synced.
        assertEquals("passkey_synced", PasskeyClassifier.kind(built, config(7, false), NOW));
        // DENY_ALL trusts nothing.
        assertEquals("passkey_synced", PasskeyClassifier.kind(built, SigninConfig.DENY_ALL, NOW));
        // The chain verifies at its time only (the test CA's leaf is valid 2000–2999).
        assertEquals("passkey_synced", PasskeyClassifier.kind(built, trusted(YUBIKEY, "security_key", "certified"), Instant.parse("1999-01-01T00:00:00Z")));
    }

    @Test
    void noneAttestationWithYubiKeyAaguidIsSynced() {
        StoredAttestation a = Fixtures.none(YUBIKEY);
        assertEquals("none", a.fmt());
        assertEquals(YUBIKEY, a.aaguid());
        assertEquals("passkey_synced", PasskeyClassifier.kind(a, trusted(YUBIKEY, "security_key", "certified"), NOW));
        // The emulator's none attestation too.
        StoredAttestation emulated = Fixtures.emulated(EmulatorUtil.NONE_ATTESTATION_AUTHENTICATOR);
        assertEquals("passkey_synced", PasskeyClassifier.kind(emulated, trusted(emulated.aaguid(), "security_key", "certified"), NOW));
    }

    @Test
    void selfAttestationIsSynced() {
        assertEquals("passkey_synced", PasskeyClassifier.kind(Fixtures.self(YUBIKEY), trusted(YUBIKEY, "security_key", "certified"), NOW));
    }

    @Test
    void backupEligibleIsSynced() {
        StoredAttestation be = Fixtures.packed(YUBIKEY, YUBIKEY, (byte) (BIT_UP | BIT_UV | BIT_BE));
        assertEquals(true, be.backupEligible());
        assertEquals("passkey_synced", PasskeyClassifier.kind(be, trusted(YUBIKEY, "security_key", "certified"), NOW));
        StoredAttestation bs = Fixtures.packed(YUBIKEY, YUBIKEY, (byte) (BIT_UP | BIT_UV | BIT_BE | BIT_BS));
        assertEquals("passkey_synced", PasskeyClassifier.kind(bs, trusted(YUBIKEY, "passkey_device", "certified"), NOW));
        // A record claiming BE=0 over authenticator data with BE=1: the authenticator data wins.
        StoredAttestation lying = new StoredAttestation(be.fmt(), be.attStmtCbor(), be.authenticatorData(), be.aaguid(), false);
        assertEquals("passkey_synced", PasskeyClassifier.kind(lying, trusted(YUBIKEY, "security_key", "certified"), NOW));
    }

    @Test
    void chainToAnotherAaguidsRootIsSynced() {
        // YUBIKEY's published root is another CA; the chain's root is published only for OTHER.
        SigninConfig cfg = config(7, false,
                entry(YUBIKEY, "security_key", "certified", root2()),
                entry(OTHER, "security_key", "certified", root3()));
        assertEquals("passkey_synced", PasskeyClassifier.kind(Fixtures.packed(YUBIKEY), cfg, NOW));
        assertEquals("security_key", PasskeyClassifier.kind(Fixtures.packed(OTHER), cfg, NOW));
        // A record whose AAGUID field names another model than its authenticator data: synced.
        StoredAttestation a = Fixtures.packed(YUBIKEY);
        StoredAttestation renamed = new StoredAttestation(a.fmt(), a.attStmtCbor(), a.authenticatorData(), OTHER, false);
        assertEquals("passkey_synced", PasskeyClassifier.kind(renamed, cfg, NOW));
    }

    @Test
    void leafAaguidExtensionMismatchIsSynced() {
        SigninConfig cfg = config(7, false,
                entry(YUBIKEY, "security_key", "certified", root3()),
                entry(OTHER, "security_key", "certified", root3()));
        // The leaf says OTHER, the authenticator data says YUBIKEY.
        assertEquals("passkey_synced", PasskeyClassifier.kind(Fixtures.packed(YUBIKEY, OTHER, (byte) (BIT_UP | BIT_UV)), cfg, NOW));
        // No extension at all is accepted ("when present").
        assertEquals("security_key", PasskeyClassifier.kind(Fixtures.packed(YUBIKEY, null, (byte) (BIT_UP | BIT_UV)), cfg, NOW));
    }

    @Test
    void platformTrustIsDeviceBound() {
        assertEquals("passkey_device", PasskeyClassifier.kind(Fixtures.packed(YUBIKEY), trusted(YUBIKEY, "passkey_device", "certified"), NOW));
    }

    @Test
    void revokedStatusIsSynced() {
        assertEquals("passkey_synced", PasskeyClassifier.kind(Fixtures.packed(YUBIKEY), trusted(YUBIKEY, "security_key", "revoked"), NOW));
        assertEquals("passkey_synced", PasskeyClassifier.kind(Fixtures.packed(YUBIKEY), trusted(YUBIKEY, "passkey_device", "revoked"), NOW));
    }

    @Test
    void unreadableOrForeignInputIsSynced() {
        StoredAttestation a = Fixtures.packed(YUBIKEY);
        SigninConfig cfg = trusted(YUBIKEY, "security_key", "certified");
        assertEquals("passkey_synced", PasskeyClassifier.kind(null, cfg, NOW));
        assertEquals("passkey_synced", PasskeyClassifier.kind(new StoredAttestation("packed", new byte[] {1, 2}, a.authenticatorData(), YUBIKEY, false), cfg, NOW));
        assertEquals("passkey_synced", PasskeyClassifier.kind(new StoredAttestation("packed", a.attStmtCbor(), new byte[] {1}, YUBIKEY, false), cfg, NOW));
        // fido-u2f has no AAGUID: never stronger than synced, whatever the list.
        assertEquals("passkey_synced", PasskeyClassifier.kind(new StoredAttestation("fido-u2f", a.attStmtCbor(), a.authenticatorData(), YUBIKEY, false), cfg, NOW));
        StoredAttestation u2f = Fixtures.emulatedU2F();
        assertEquals("fido-u2f", u2f.fmt());
        assertEquals("passkey_synced", PasskeyClassifier.kind(u2f, trusted(u2f.aaguid(), "security_key", "certified"), NOW));
        assertThrows(IllegalArgumentException.class, () -> PasskeyClassifier.parse(new byte[] {0x01}));
    }

    @Test
    void parseKeepsTheParts() {
        StoredAttestation a = Fixtures.packed(YUBIKEY);
        assertArrayEquals(new byte[] {9, 8, 7, 6}, PasskeyClassifier.credentialId(a));
        assertEquals(2, PasskeyClassifier.x5c(a).size());
        assertEquals(0, PasskeyClassifier.x5c(Fixtures.none(YUBIKEY)).size());
    }

    @Test
    void reclassifyRules() {
        StoredAttestation a = Fixtures.packed(YUBIKEY);
        SigninConfig sk = trusted(YUBIKEY, "security_key", "certified");
        SigninConfig dev = trusted(YUBIKEY, "passkey_device", "certified");
        SigninConfig revoked = trusted(YUBIKEY, "security_key", "revoked");
        SigninConfig missing = config(8, false);
        assertEquals("security_key", PasskeyClassifier.reclassify("passkey_synced", null, a, sk, NOW));
        assertEquals("passkey_device", PasskeyClassifier.reclassify("passkey_synced", "passkey_device", a, sk, NOW));
        assertEquals("passkey_synced", PasskeyClassifier.reclassify("passkey_synced", "passkey_synced", a, sk, NOW));
        assertEquals("security_key", PasskeyClassifier.reclassify("security_key", null, a, dev, NOW), "never down for a weaker kind");
        assertEquals("security_key", PasskeyClassifier.reclassify("security_key", null, a, missing, NOW), "never down for a missing entry");
        assertEquals("passkey_synced", PasskeyClassifier.reclassify("security_key", null, a, revoked, NOW), "down for revoked");
        assertEquals("passkey_synced", PasskeyClassifier.reclassify("nonsense", null, a, sk, NOW));
        assertEquals("passkey_synced", PasskeyClassifier.reclassify("passkey_synced", "garbage", a, sk, NOW), "an unknown cap caps at synced");
        assertEquals("passkey_device", PasskeyClassifier.reclassify("passkey_device", "garbage", a, sk, NOW), "and never lowers");
    }
}
