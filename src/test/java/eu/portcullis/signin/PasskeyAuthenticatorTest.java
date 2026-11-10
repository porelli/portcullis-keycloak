package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
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

    private static PasskeyAuthenticator authenticator(Flow f, SigninConfig cfg) {
        return new PasskeyAuthenticator(f.session, () -> cfg);
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
}
