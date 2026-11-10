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
    /**
     * The classifier trusts Keycloak's registration check for the attestation
     * signature: with core's policy (attestation {@code direct}), the
     * extension's registration manager refuses a forged signature over a
     * trusted chain, and accepts the emulators' real packed and {@code none}
     * registrations.
     */
    @Test
    void registrationChecksTheAttestationSignature() {
        org.keycloak.models.WebAuthnPolicy policy = new org.keycloak.models.WebAuthnPolicy();
        policy.setAttestationConveyancePreference("direct");
        com.webauthn4j.WebAuthnRegistrationManager m = new PasskeyRegister(null).createWebAuthnRegistrationManager(policy);

        Fixtures.Registration forged = Fixtures.forgedPacked(Fixtures.YUBIKEY);
        // The same bytes classify as a security key: only the signature check stands in the way.
        assertEquals("security_key", PasskeyClassifier.kind(PasskeyClassifier.parse(forged.attestationObject()),
                Fixtures.config(1, false, Fixtures.entry(Fixtures.YUBIKEY, "security_key", "certified", Fixtures.root3())),
                java.time.Instant.parse("2026-11-10T00:00:00Z")));
        org.junit.jupiter.api.Assertions.assertThrows(com.webauthn4j.verifier.exception.BadSignatureException.class,
                () -> verify(m, forged));

        verify(m, Fixtures.register(com.webauthn4j.test.EmulatorUtil.PACKED_AUTHENTICATOR));
        verify(m, Fixtures.register(com.webauthn4j.test.EmulatorUtil.NONE_ATTESTATION_AUTHENTICATOR));
    }

    private static void verify(com.webauthn4j.WebAuthnRegistrationManager m, Fixtures.Registration r) {
        var data = m.parse(new com.webauthn4j.data.RegistrationRequest(r.attestationObject(), r.clientDataJSON()));
        m.verify(data, new com.webauthn4j.data.RegistrationParameters(
                com.webauthn4j.server.ServerProperty.builder().origin(Fixtures.ORIGIN).rpId(Fixtures.RP_ID).challenge(r.challenge()).build(),
                List.of(new com.webauthn4j.data.PublicKeyCredentialParameters(
                        com.webauthn4j.data.PublicKeyCredentialType.PUBLIC_KEY,
                        com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier.ES256)),
                false));
    }

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
