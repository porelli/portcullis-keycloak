package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.common.util.Base64Url;
import org.keycloak.forms.login.freemarker.model.WebAuthnAuthenticatorsBean;

class PasskeyAuthenticatorTest {
    static final byte[] SYNCED_ID = Flow.bytes("synced-credential");
    static final byte[] DEVICE_ID = Flow.bytes("device-credential");
    static final byte[] KEY_ID = Flow.bytes("security-key-credential");

    private static Flow.Person alice(Flow f) {
        return f.person("u-alice", "alice")
                .passkey(PasskeyClassifier.TYPE_SYNCED, SYNCED_ID)
                .passkey(PasskeyClassifier.TYPE_DEVICE, DEVICE_ID)
                .passkey(PasskeyClassifier.TYPE_SECURITY_KEY, KEY_ID);
    }

    /** The AAGUID of every test passkey's store row (a model the trust list doesn't list unless a test adds it). */
    static final String MODEL = "cb69481e-8ff7-4039-93ec-0a2729a154a8";

    private static PasskeyAuthenticator authenticator(Flow f, SigninConfig cfg) {
        return authenticator(f, cfg, id -> Optional.of(MODEL));
    }

    private static PasskeyAuthenticator authenticator(Flow f, SigninConfig cfg, Function<String, Optional<String>> aaguidOf) {
        return new PasskeyAuthenticator(f.session, () -> cfg, aaguidOf);
    }

    /** The four default methods with one trust-list entry for MODEL ({@code roots: []} is valid only for revoked). */
    private static SigninConfig withModel(String kind, String status) {
        String body = """
            {"version": 1, "methods": [%s], "add_stronger": false, "templates": {}, "clients": {},
             "authenticators": {"%s": {"kind": "%s", "status": "%s", "roots": []}},
             "mds": {"serial": 1, "next_update": "2026-12-01T00:00:00Z"}}
            """.formatted(Configs.DEFAULT_METHODS, MODEL, kind, status);
        try {
            return SigninConfig.parse(body.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<String> allowed(Flow f) {
        WebAuthnAuthenticatorsBean bean = (WebAuthnAuthenticatorsBean) f.formAttributes.get(WebAuthnConstants.ALLOWED_AUTHENTICATORS);
        return bean.getAuthenticators().stream().map(WebAuthnAuthenticatorsBean.WebAuthnAuthenticatorBean::getCredentialId).toList();
    }

    @Test
    void allowCredentialsFollowRequestedKind() {
        Flow f = new Flow();
        f.user = alice(f).model; // a step-up: auth-cookie set the person
        f.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key");
        authenticator(f, Configs.plain()).authenticate(f.context);
        assertEquals(FlowStatus.CHALLENGE, f.status);
        assertEquals("webauthn-authenticate", f.page);
        assertEquals(List.of(Base64Url.encode(KEY_ID)), allowed(f));
        assertEquals("true", f.formAttributes.get(WebAuthnConstants.IS_USER_IDENTIFIED));

        Flow any = new Flow(); // pc_method=passkey: every kind, in the kinds' order
        any.user = alice(any).model;
        any.clientNotes.put(PcMethod.CLIENT_NOTE, "passkey");
        authenticator(any, Configs.plain()).authenticate(any.context);
        assertEquals(List.of(Base64Url.encode(SYNCED_ID), Base64Url.encode(DEVICE_ID), Base64Url.encode(KEY_ID)), allowed(any));
    }

    @Test
    void stepsAsideForAnotherMethodOrNoCredential() {
        Flow f = new Flow();
        f.user = alice(f).model;
        f.clientNotes.put(PcMethod.CLIENT_NOTE, "yubikey_cert");
        authenticator(f, Configs.plain()).authenticate(f.context);
        assertEquals(FlowStatus.ATTEMPTED, f.status);

        Flow none = new Flow();
        none.user = none.person("u-bob", "bob").passkey(PasskeyClassifier.TYPE_SYNCED, SYNCED_ID).model;
        none.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key");
        authenticator(none, Configs.plain()).authenticate(none.context);
        assertEquals(FlowStatus.ATTEMPTED, none.status, "no security key: nothing to offer");

        Flow off = new Flow();
        authenticator(off, SigninConfig.DENY_ALL).authenticate(off.context);
        assertEquals(FlowStatus.ATTEMPTED, off.status, "every kind off");
    }

    /** A posted assertion of credential id for alice (discoverable: the user handle names her). */
    private static void post(Flow f, byte[] credentialId) {
        f.form.putSingle(WebAuthnConstants.CREDENTIAL_ID, Base64Url.encode(credentialId));
        f.form.putSingle(WebAuthnConstants.USER_HANDLE, Base64Url.encode("u-alice".getBytes(StandardCharsets.UTF_8)));
        f.form.putSingle(WebAuthnConstants.CLIENT_DATA_JSON, Base64Url.encode(Flow.bytes("{}")));
        f.form.putSingle(WebAuthnConstants.AUTHENTICATOR_DATA, Base64Url.encode(new byte[37]));
        f.form.putSingle(WebAuthnConstants.SIGNATURE, Base64Url.encode(new byte[8]));
        f.authNotes.put(WebAuthnConstants.AUTH_CHALLENGE_NOTE, Base64Url.encode(new byte[32]));
    }

    @Test
    void acceptsAllThreeTypes() {
        String[][] cases = {
            {PasskeyClassifier.TYPE_SYNCED, "passkey_synced"},
            {PasskeyClassifier.TYPE_DEVICE, "passkey_device"},
            {PasskeyClassifier.TYPE_SECURITY_KEY, "security_key"},
        };
        byte[][] ids = {SYNCED_ID, DEVICE_ID, KEY_ID};
        for (int i = 0; i < cases.length; i++) {
            Flow f = new Flow();
            Flow.Person alice = alice(f);
            post(f, ids[i]);
            authenticator(f, Configs.plain()).action(f.context);
            assertEquals(FlowStatus.SUCCESS, f.status, cases[i][1]);
            assertEquals(alice.model, f.user);
            assertEquals(cases[i][1], f.authNotes.get(PasskeyAuthenticator.KIND_NOTE));
            // Keycloak verified it through that type's credential provider.
            assertEquals(cases[i][0], alice.checked.get(alice.checked.size() - 1).getType());
        }
    }

    @Test
    void refusesAnotherKindThanRequestedOrAFailedCheck() {
        Flow f = new Flow();
        Flow.Person alice = alice(f);
        f.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key");
        post(f, SYNCED_ID);
        authenticator(f, Configs.plain()).action(f.context);
        assertEquals(FlowStatus.FAILED, f.status);
        assertTrue(alice.checked.isEmpty(), "never verified");
        assertNull(f.authNotes.get(PasskeyAuthenticator.KIND_NOTE));

        Flow off = new Flow(); // the device-bound kind switched off
        alice(off);
        post(off, DEVICE_ID);
        authenticator(off, Configs.of("\"passkey_synced\", \"security_key\"", false, "", "")).action(off.context);
        assertEquals(FlowStatus.FAILED, off.status);

        Flow bad = new Flow();
        Flow.Person a = alice(bad);
        a.passkeyValid = in -> false;
        post(bad, KEY_ID);
        authenticator(bad, Configs.plain()).action(bad.context);
        assertFalse(bad.status == FlowStatus.SUCCESS);
        assertNull(bad.authNotes.get(PasskeyAuthenticator.KIND_NOTE));
    }

    /**
     * A revoked model signs in as synced until reclassification rewrites
     * the credential's type: its stored kind (device / security key) is
     * never what the session gets, and it is refused where synced isn't
     * accepted. A missing store row counts the same (fail closed).
     */
    @Test
    void revokedModelSignsInAsSynced() {
        byte[][] ids = {DEVICE_ID, KEY_ID};
        String[] kinds = {"passkey_device", "security_key"};
        for (int i = 0; i < ids.length; i++) {
            Flow f = new Flow();
            Flow.Person alice = alice(f);
            post(f, ids[i]);
            authenticator(f, withModel(kinds[i], "revoked")).action(f.context);
            assertEquals(FlowStatus.SUCCESS, f.status, kinds[i]);
            assertEquals("passkey_synced", f.authNotes.get(PasskeyAuthenticator.KIND_NOTE), kinds[i] + " of a revoked model");
            // Still verified through its stored type's provider.
            assertEquals(PasskeyClassifier.typeOf(kinds[i]), alice.checked.get(alice.checked.size() - 1).getType());

            // pc_method asks for the stored kind: refused, never verified.
            Flow asked = new Flow();
            Flow.Person a = alice(asked);
            asked.clientNotes.put(PcMethod.CLIENT_NOTE, kinds[i]);
            post(asked, ids[i]);
            authenticator(asked, withModel(kinds[i], "revoked")).action(asked.context);
            assertEquals(FlowStatus.FAILED, asked.status, kinds[i] + " asked for, model revoked");
            assertTrue(a.checked.isEmpty(), "never verified");
            assertNull(asked.authNotes.get(PasskeyAuthenticator.KIND_NOTE));

            // A certified entry keeps the stored kind.
            Flow ok = new Flow();
            alice(ok);
            post(ok, ids[i]);
            // A certified entry needs a root: use the plain config (MODEL unlisted) for "not revoked".
            authenticator(ok, Configs.plain()).action(ok.context);
            assertEquals(kinds[i], ok.authNotes.get(PasskeyAuthenticator.KIND_NOTE));

            // No store row: synced (fail closed).
            Flow norow = new Flow();
            alice(norow);
            post(norow, ids[i]);
            authenticator(norow, Configs.plain(), id -> Optional.empty()).action(norow.context);
            assertEquals("passkey_synced", norow.authNotes.get(PasskeyAuthenticator.KIND_NOTE), kinds[i] + " without a row");

            // The row can't be read: synced too.
            Flow broken = new Flow();
            alice(broken);
            post(broken, ids[i]);
            authenticator(broken, Configs.plain(), id -> { throw new IllegalStateException("db down"); }).action(broken.context);
            assertEquals("passkey_synced", broken.authNotes.get(PasskeyAuthenticator.KIND_NOTE), kinds[i] + " with an unreadable row");
        }
        // The row lookup gets the Keycloak credential id of the passkey used.
        Flow f = new Flow();
        alice(f);
        post(f, KEY_ID);
        Map<String, String> rows = Map.of(PasskeyClassifier.TYPE_SECURITY_KEY + "-0", MODEL);
        authenticator(f, withModel("security_key", "revoked"), id -> Optional.ofNullable(rows.get(id))).action(f.context);
        assertEquals("passkey_synced", f.authNotes.get(PasskeyAuthenticator.KIND_NOTE));
        // A synced passkey of a revoked model is synced anyway.
        Flow s2 = new Flow();
        alice(s2);
        post(s2, SYNCED_ID);
        authenticator(s2, withModel("security_key", "revoked")).action(s2.context);
        assertEquals("passkey_synced", s2.authNotes.get(PasskeyAuthenticator.KIND_NOTE));
    }
}
