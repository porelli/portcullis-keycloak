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

    /** A RequiredActionContext over a Flow's authentication session, with its own (later) event builder. */
    private static final class Action {
        final Flow signIn = new Flow();
        final Flow later = new Flow();
        org.keycloak.authentication.RequiredActionContext.Status status;
        final org.keycloak.authentication.RequiredActionContext context;

        Action(org.keycloak.models.UserModel user) {
            context = Fake.named("required action")
                    .on("getAuthenticationSession", a -> signIn.authSession)
                    .on("getEvent", a -> later.event)
                    .on("getUser", a -> user)
                    .on("success", a -> status = org.keycloak.authentication.RequiredActionContext.Status.SUCCESS)
                    .on("challenge", a -> status = org.keycloak.authentication.RequiredActionContext.Status.CHALLENGE)
                    .on("getStatus", a -> status)
                    .as(org.keycloak.authentication.RequiredActionContext.class);
            History.onSuccess(signIn.context, Set.of("passkey_synced"), Set.of("passkey_synced"), "sign_in");
        }
    }

    private static org.keycloak.models.UserModel withSyncedPasskey() {
        org.keycloak.models.SubjectCredentialManager creds = Fake.named("credentials")
                .on("getStoredCredentialsByTypeStream", a -> PasskeyClassifier.TYPE_SYNCED.equals(a[0])
                        ? java.util.stream.Stream.of(new org.keycloak.credential.CredentialModel())
                        : java.util.stream.Stream.empty())
                .as(org.keycloak.models.SubjectCredentialManager.class);
        return Fake.named("alice").ret("credentialManager", creds).ret("getUsername", "alice")
                .as(org.keycloak.models.UserModel.class);
    }

    /** skip_if_exists with a passkey: success in this request, so the LOGIN carries the sign-in's details. */
    @Test
    void skipIfExistsReappliesTheHistoryDetails() {
        Action r = new Action(withSyncedPasskey());
        r.signIn.clientNotes.put(org.keycloak.models.Constants.KC_ACTION_PARAMETER,
                org.keycloak.models.Constants.KC_ACTION_PARAMETER_SKIP_IF_EXISTS);
        new PasskeyRegister(null).requiredActionChallenge(r.context);
        assertEquals(org.keycloak.authentication.RequiredActionContext.Status.SUCCESS, r.status);
        assertEquals("sign_in", r.later.eventDetails().get(History.KIND));
        assertEquals("passkey_synced", r.later.eventDetails().get(History.METHODS));
    }

    /** processAction: the details only on success (a refusal or a retry leaves the builder alone). */
    @Test
    void processActionReappliesOnSuccessOnly() {
        Action ok = new Action(withSyncedPasskey());
        new PasskeyRegister(null) {
            @Override
            void register(org.keycloak.authentication.RequiredActionContext c) {
                c.success();
            }
        }.processAction(ok.context);
        assertEquals("sign_in", ok.later.eventDetails().get(History.KIND));
        assertEquals("passkey_synced", ok.later.eventDetails().get(History.SESSION));

        Action refused = new Action(withSyncedPasskey());
        new PasskeyRegister(null) {
            @Override
            void register(org.keycloak.authentication.RequiredActionContext c) {
                c.challenge(null);
            }
        }.processAction(refused.context);
        assertFalse(refused.later.eventDetails().containsKey(History.KIND));
    }
}
