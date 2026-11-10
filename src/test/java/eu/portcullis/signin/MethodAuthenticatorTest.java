package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.FlowStatus;

class MethodAuthenticatorTest {
    private static Flow run(SigninConfig cfg, Map<String, String> config, String kindUsed) {
        Flow f = new Flow();
        if (config != null) {
            f.config(config);
        }
        if (kindUsed != null) {
            f.authNotes.put(PasskeyAuthenticator.KIND_NOTE, kindUsed);
        }
        new MethodAuthenticator(() -> cfg).authenticate(f.context);
        return f;
    }

    private static Map<String, String> method(String m, String ref) {
        return Map.of("method", m, "default.reference.value", ref);
    }

    @Test
    void refusesSwitchedOffMethod() {
        Flow f = run(Configs.plain(), method("password", "pwd"), null); // password is off
        assertEquals(FlowStatus.FAILED, f.status);
        assertEquals(AuthenticationFlowError.ACCESS_DENIED, f.error);
        Flow deny = run(SigninConfig.DENY_ALL, method("security_key", "hwk"), "security_key");
        assertEquals(AuthenticationFlowError.ACCESS_DENIED, deny.error);
    }

    @Test
    void succeedsWhileOn() {
        assertEquals(FlowStatus.SUCCESS, run(Configs.plain(), method("security_key", "hwk"), "security_key").status);
        assertEquals(FlowStatus.SUCCESS, run(Configs.of(Configs.WITH_PASSWORD, false, "", ""), method("password", "pwd"), null).status);
    }

    @Test
    void refusesMisconfiguration() {
        SigninConfig cfg = Configs.plain();
        assertEquals(FlowStatus.FAILED, run(cfg, null, "security_key").status, "no config");
        assertEquals(FlowStatus.FAILED, run(cfg, method("webauthn", "hwk"), "security_key").status, "unknown method");
        assertEquals(FlowStatus.FAILED, run(cfg, method("security_key", "spk"), "security_key").status, "wrong reference value");
        assertEquals(FlowStatus.FAILED, run(cfg, method("security_key", "hwk"), "passkey_synced").status, "another kind signed in");
        assertEquals(FlowStatus.FAILED, run(cfg, method("security_key", "hwk"), null).status, "no passkey signed in");
    }
}
