package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationSelectionOption;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;

/**
 * Keycloak's AuthenticationSelectionResolver runs the first selectable
 * execution and lists non-credential executions before the credential ones
 * that need no user: portcullis-passkey must not be a CredentialValidator, so
 * the flow's own order (passkey before the password form) decides, and the
 * "Try another way" choices hold only usable methods.
 */
class OfferTest {
    @Test
    void passkeyIsNoCredentialValidator() {
        assertFalse(new PasskeyAuthenticator(null, Configs::plain) instanceof CredentialValidator);
        assertFalse(new PasswordForm(Configs::plain) instanceof CredentialValidator);
    }

    private static AuthenticationSelectionOption option(Flow f, String authenticator) {
        return option(f, authenticator, null);
    }

    /** The CA files of the two X.509 executions. */
    private static final Map<String, Path> CAS = cas();

    private static Map<String, Path> cas() {
        try {
            Path dir = Files.createTempDirectory("offer-cas");
            dir.toFile().deleteOnExit();
            return Map.of("yubikey_cert", TestCas.YUBIKEY.pem(dir, "yubikey-ca.pem"), "browser_cert", TestCas.BROWSER.pem(dir, "browser-ca.pem"));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** f presents leaf (null: no certificate). */
    private static Flow presenting(Flow f, X509Certificate leaf) {
        f.certificates = leaf == null ? null : new X509Certificate[] {leaf};
        return f;
    }

    private static Flow yubikeyLeaf() {
        return presenting(new Flow(), TestCas.YUBIKEY.leaf("alice"));
    }

    private static Flow browserLeaf() {
        return presenting(new Flow(), TestCas.BROWSER.leaf("alice"));
    }

    /**
     * An execution of authenticator, with a config holding portcullis.method
     * = method and, for a certificate method, its CA file (null: no config).
     */
    private static AuthenticationSelectionOption option(Flow f, String authenticator, String method) {
        AuthenticationExecutionModel e = new AuthenticationExecutionModel();
        e.setId("exec-" + authenticator + (method == null ? "" : "-" + method));
        e.setAuthenticator(authenticator);
        if (method != null) {
            AuthenticatorConfigModel c = new AuthenticatorConfigModel();
            c.setId("cfg-" + method);
            Map<String, String> config = new HashMap<>(Map.of(X509Authenticator.METHOD_CONFIG, method));
            if (CAS.containsKey(method)) {
                config.put(X509Authenticator.CA_CONFIG, CAS.get(method).toString());
            }
            c.setConfig(config);
            f.configs.put(c.getId(), c);
            e.setAuthenticatorConfig(c.getId());
        }
        return new AuthenticationSelectionOption(f.session, e);
    }

    /** What "Try another way" keeps, by authenticator (an X.509 execution as portcullis-x509:<method>). */
    private static List<String> offered(Flow f, SigninConfig cfg) {
        f.selections = new ArrayList<>(List.of(option(f, PasskeyAuthenticatorFactory.PROVIDER_ID),
                option(f, PasswordFormFactory.PROVIDER_ID), option(f, X509AuthenticatorFactory.PROVIDER_ID, "yubikey_cert"),
                option(f, X509AuthenticatorFactory.PROVIDER_ID, "browser_cert"), option(f, X509AuthenticatorFactory.PROVIDER_ID, "mtls"),
                option(f, X509AuthenticatorFactory.PROVIDER_ID)));
        new PasskeyAuthenticator(f.session, () -> cfg).authenticate(f.context);
        return f.selections.stream().map(o -> {
            AuthenticationExecutionModel e = o.getAuthenticationExecution();
            if (!X509AuthenticatorFactory.PROVIDER_ID.equals(e.getAuthenticator())) {
                return e.getAuthenticator();
            }
            return e.getAuthenticator() + ":" + X509Authenticator.method(f.configs.get(e.getAuthenticatorConfig()));
        }).toList();
    }

    @Test
    void tryAnotherWayOffersOnlyUsableMethods() {
        SigninConfig on = Configs.of(Configs.WITH_PASSWORD, false, "", "");
        assertEquals(List.of("portcullis-passkey", "portcullis-password-form", "portcullis-x509:yubikey_cert"), offered(yubikeyLeaf(), on));
        assertEquals(List.of("portcullis-passkey", "portcullis-x509:yubikey_cert"), offered(yubikeyLeaf(), Configs.plain()), "password off");
        Flow step = yubikeyLeaf();
        step.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key");
        assertEquals(List.of("portcullis-passkey"), offered(step, on), "pc_method asks for a passkey kind");
        Flow admin = yubikeyLeaf();
        admin.user = admin.person("u-admin", "admin").passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s")).model;
        assertEquals(List.of("portcullis-passkey", "portcullis-x509:yubikey_cert"), offered(admin, on), "admin never gets a password");
    }

    /** The code's row only with a known person who may use one and has one, totp on and allowed. */
    @Test
    void otpOnlyWithKnownUserAndCredential() {
        SigninConfig on = Configs.of(Configs.WITH_TOTP, false, "", "");
        Flow nobody = new Flow();
        assertFalse(offeredWithOtp(nobody, on).contains("portcullis-otp"), "nobody known");
        Flow none = new Flow();
        none.user = none.person("u-alice", "alice").model;
        assertFalse(offeredWithOtp(none, on).contains("portcullis-otp"), "no otp credential");
        Flow alice = new Flow();
        alice.user = alice.person("u-alice", "alice").otp("otp-1", "phone").model;
        assertEquals(List.of("portcullis-passkey", "portcullis-password-form", "portcullis-otp"), offeredWithOtp(alice, on));
        Flow off = new Flow();
        off.user = off.person("u-alice", "alice").otp("otp-1", "phone").model;
        assertFalse(offeredWithOtp(off, Configs.of(Configs.WITH_PASSWORD, false, "", "")).contains("portcullis-otp"), "totp off");
        Flow asked = new Flow();
        asked.user = asked.person("u-alice", "alice").otp("otp-1", "phone").model;
        asked.clientNotes.put(PcMethod.CLIENT_NOTE, "security_key");
        assertFalse(offeredWithOtp(asked, on).contains("portcullis-otp"), "pc_method asks another");
        Flow code = new Flow();
        code.user = code.person("u-alice", "alice").otp("otp-1", "phone").model;
        code.clientNotes.put(PcMethod.CLIENT_NOTE, "totp");
        assertEquals(List.of("portcullis-otp"), offeredWithOtp(code, on).stream().filter(s -> !s.equals("portcullis-passkey")).toList());
        Flow admin = new Flow();
        admin.user = admin.person("u-admin", "admin").otp("otp-1", "phone").model;
        assertFalse(offeredWithOtp(admin, on).contains("portcullis-otp"), "admin");
    }

    private static List<String> offeredWithOtp(Flow f, SigninConfig cfg) {
        f.selections = new ArrayList<>(List.of(option(f, PasskeyAuthenticatorFactory.PROVIDER_ID),
                option(f, PasswordFormFactory.PROVIDER_ID), option(f, OtpAuthenticatorFactory.PROVIDER_ID)));
        Offer.usableOnly(f.context, cfg);
        return f.selections.stream().map(o -> o.getAuthenticationExecution().getAuthenticator()).toList();
    }

    @Test
    void browserExecutionOfferedOnlyWhenBrowserCertOn() {
        SigninConfig on = Configs.of(X509AuthenticatorTest.ALL, false, "", "");
        assertEquals(List.of("portcullis-passkey", "portcullis-x509:browser_cert"), offered(browserLeaf(), on));
        assertEquals(List.of("portcullis-passkey"), offered(browserLeaf(), Configs.plain()), "browser_cert off");
        Flow asked = browserLeaf();
        asked.clientNotes.put(PcMethod.CLIENT_NOTE, "browser_cert");
        // The passkey's own execution steps aside then, but the list is still trimmed.
        assertEquals(List.of("portcullis-x509:browser_cert"), offered(asked, on).stream().filter(s -> s.startsWith("portcullis-x509")).toList());
        SigninConfig browserOnly = Configs.of("\"browser_cert\", \"passkey_synced\"", false, "", "");
        assertEquals(List.of("portcullis-passkey", "portcullis-x509:browser_cert"), offered(browserLeaf(), browserOnly), "yubikey_cert off");
    }

    /**
     * Both X.509 executions show the provider's one display name: a row only
     * for the execution whose CA issued the presented leaf, none without a
     * leaf (neither could sign in), none for a leaf only named as issued.
     */
    @Test
    void certificateRowOnlyForTheCaOfThePresentedLeaf() {
        SigninConfig all = Configs.of(X509AuthenticatorTest.ALL, false, "", "");
        assertEquals(List.of("portcullis-passkey"), offered(new Flow(), all), "no certificate: no certificate row");
        assertEquals(List.of("portcullis-passkey", "portcullis-x509:yubikey_cert"), offered(yubikeyLeaf(), all));
        assertEquals(List.of("portcullis-passkey", "portcullis-x509:browser_cert"), offered(browserLeaf(), all));
        Flow forged = presenting(new Flow(), TestCas.issue(TestCas.YUBIKEY.cert(), TestCas.BROWSER.key(), "alice"));
        assertEquals(List.of("portcullis-passkey"), offered(forged, all), "named as the YubiKey CA's, signed by another key");
        Flow other = presenting(new Flow(), TestCas.selfSigned("CN=alice, O=Elsewhere"));
        assertEquals(List.of("portcullis-passkey"), offered(other, all), "another CA's leaf");
    }
}
