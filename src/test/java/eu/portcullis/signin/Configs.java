package eu.portcullis.signin;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** signin-keycloak.json documents for the authenticators' tests. */
final class Configs {
    private Configs() {}

    static final String DEFAULT_METHODS = "\"passkey_device\", \"passkey_synced\", \"security_key\", \"yubikey_cert\"";
    static final String WITH_PASSWORD = "\"passkey_device\", \"passkey_synced\", \"password\", \"security_key\", \"yubikey_cert\"";

    /** The default methods plus password and totp (sorted, as the Hub writes them). */
    static final String WITH_TOTP = "\"passkey_device\", \"passkey_synced\", \"password\", \"security_key\", \"totp\", \"yubikey_cert\"";
    /** The built-in password-and-code: all of password, totp. */
    static final String PASSWORD_AND_CODE = "{\"op\": \"all\", \"items\": [\"password\", \"totp\"]}";

    static final String STANDARD = """
        {"op": "any", "items": [
          {"op": "any", "items": ["passkey_synced", "passkey_device", "security_key"]},
          {"op": "any", "items": ["yubikey_cert"]}]}""";
    static final String STRONG = "{\"op\": \"any\", \"items\": [\"security_key\", \"yubikey_cert\"]}";
    static final String YUBIKEY_AND_CERT = "{\"op\": \"all\", \"items\": [\"yubikey_cert\", \"security_key\"]}";
    static final String SYNCED_AND_KEY = "{\"op\": \"all\", \"items\": [\"passkey_synced\", \"security_key\"]}";

    /** methods (a JSON list body), add_stronger, templates and clients (JSON object bodies). */
    static SigninConfig of(String methods, boolean addStronger, String templates, String clients) {
        String body = """
            {"version": 1, "methods": [%s], "add_stronger": %s, "templates": {%s}, "clients": {%s},
             "authenticators": {}, "mds": {"serial": 1, "next_update": "2026-12-01T00:00:00Z"}}
            """.formatted(methods, addStronger, templates, clients);
        try {
            SigninConfig c = SigninConfig.parse(body.getBytes(StandardCharsets.UTF_8));
            if (c == SigninConfig.DENY_ALL) {
                throw new IllegalStateException("test config refused");
            }
            return c;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The four default methods, no templates or clients. */
    static SigninConfig plain() {
        return of(DEFAULT_METHODS, false, "", "");
    }

    /** One client "nextcloud" (name "Nextcloud") on template t (a compiled rule). */
    static SigninConfig client(String methods, boolean addStronger, String rule) {
        return of(methods, addStronger, "\"t\": " + rule, "\"nextcloud\": {\"template\": \"t\", \"name\": \"Nextcloud\"}");
    }
}
