package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;

/**
 * The certificate step with Keycloak's own X.509 code: a certificate maps to
 * its account by CN (core's mapping: Subject's Common Name → username), and a
 * certificate of another account never signs in during someone's sign-in.
 */
class X509StepTest {
    /**
     * Keycloak's crypto module (BouncyCastle FIPS or not) isn't on the test
     * classpath: its X.500 name extractor is stood in for by the JDK's LDAP
     * name parser (Keycloak's own CN mapping, extractor and user mapper run).
     */
    static {
        crypto();
    }

    static synchronized void crypto() {
        if (!org.keycloak.common.crypto.CryptoIntegration.isInitialised()) {
            org.keycloak.common.crypto.UserIdentityExtractorProvider names = new org.keycloak.common.crypto.UserIdentityExtractorProvider() {
                @Override
                public org.keycloak.common.crypto.UserIdentityExtractor getX500NameExtractor(String attr,
                        java.util.function.Function<X509Certificate[], java.security.Principal> principal) {
                    return certs -> {
                        try {
                            for (javax.naming.ldap.Rdn rdn : new javax.naming.ldap.LdapName(principal.apply(certs).getName()).getRdns()) {
                                if (rdn.getType().equalsIgnoreCase(attr)) {
                                    return rdn.getValue().toString();
                                }
                            }
                            return null;
                        } catch (javax.naming.InvalidNameException e) {
                            return null;
                        }
                    };
                }

                @Override
                public SubjectAltNameExtractor getSubjectAltNameExtractor(int generalName) {
                    throw new UnsupportedOperationException();
                }
            };
            org.keycloak.common.crypto.CryptoIntegration.setProvider(Fake.named("crypto")
                    .ret("getIdentityExtractorProvider", names).as(org.keycloak.common.crypto.CryptoProvider.class));
        }
    }

    /** A YubiKey certificate (the test pki_int) for cn. */
    static X509Certificate certificate(String cn) {
        return TestCas.YUBIKEY.leaf(cn);
    }

    /** The CA files of the two executions (written once). */
    static final Path YUBIKEY_CA = caFile(TestCas.YUBIKEY, "yubikey");
    static final Path BROWSER_CA = caFile(TestCas.BROWSER, "browser");

    private static Path caFile(TestCas.Ca ca, String name) {
        try {
            Path p = Files.createTempFile("portcullis-" + name + "-ca", ".pem");
            p.toFile().deleteOnExit();
            Files.writeString(p, TestCas.pem(ca.cert()));
            return p;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The two executions' configs (contract §8.1 "Flows"): x509-config and x509-browser-config. */
    static Map<String, String> yubikeyConfig() {
        Map<String, String> c = new HashMap<>(X509);
        c.put(X509Authenticator.METHOD_CONFIG, "yubikey_cert");
        c.put(X509Authenticator.CA_CONFIG, YUBIKEY_CA.toString());
        return c;
    }

    static Map<String, String> browserConfig() {
        Map<String, String> c = new HashMap<>(X509);
        c.put(X509Authenticator.METHOD_CONFIG, "browser_cert");
        c.put(X509Authenticator.CA_CONFIG, BROWSER_CA.toString());
        c.put("default.reference.value", "file");
        return c;
    }

    static final Map<String, String> X509 = Map.of(
            AbstractX509ClientCertificateAuthenticator.MAPPING_SOURCE_SELECTION, AbstractX509ClientCertificateAuthenticator.MAPPING_SOURCE_CERT_SUBJECTDN_CN,
            AbstractX509ClientCertificateAuthenticator.USER_MAPPER_SELECTION, AbstractX509ClientCertificateAuthenticator.USERNAME_EMAIL_MAPPER,
            AbstractX509ClientCertificateAuthenticator.CONFIRMATION_PAGE_DISALLOWED, "true",
            "default.reference.value", "mtls");

    /** alice signed in with her security key; mallory exists too; the request presents cn's certificate. */
    static Flow step(String cn) {
        return step(cn == null ? null : certificate(cn));
    }

    /** The same with this leaf presented (null: none); the flow holds both x509 executions. */
    static Flow step(X509Certificate leaf) {
        Flow f = new Flow();
        f.user = f.person("u-alice", "alice").passkey(PasskeyClassifier.TYPE_SECURITY_KEY, Flow.bytes("k")).model;
        f.person("u-mallory", "mallory");
        f.certificates = leaf == null ? null : new X509Certificate[] {leaf};
        f.config(yubikeyConfig());
        // The flow holds the two portcullis-x509 executions in a sub-flow, each with its config.
        AuthenticationExecutionModel sub = new AuthenticationExecutionModel();
        sub.setAuthenticatorFlow(true);
        sub.setFlowId("flow-signin");
        f.flows.put("flow-top", List.of(sub));
        f.flows.put("flow-signin", List.of(x509(f, "cfg-x509", yubikeyConfig()), x509(f, "cfg-x509-browser", browserConfig())));
        return f;
    }

    private static AuthenticationExecutionModel x509(Flow f, String id, Map<String, String> config) {
        AuthenticationExecutionModel x509 = new AuthenticationExecutionModel();
        x509.setAuthenticator(X509AuthenticatorFactory.PROVIDER_ID);
        x509.setAuthenticatorConfig(id);
        AuthenticatorConfigModel c = new AuthenticatorConfigModel();
        c.setId(id);
        c.setConfig(new HashMap<>(config));
        f.configs.put(id, c);
        return x509;
    }

    @Test
    void anotherPersonsCertificateOnTheStepFails() throws Exception {
        Flow f = step("mallory");
        UserModel alice = f.user;
        f.authNotes.put(PcMethod.STEP_NOTE, "yubikey_cert");
        new X509Authenticator(false, Configs::plain).authenticate(f.context);
        assertEquals(FlowStatus.FAILED, f.status);
        assertEquals(AuthenticationFlowError.USER_CONFLICT, f.error);
        assertNull(f.user, "nobody is left set");
        assertNull(f.authNotes.get(X509Authenticator.METHOD_NOTE));
        assertTrue(alice != null);

        // Keycloak's own processor refuses the switch too; the stock code then answers attempted.
        Flow strict = step("mallory");
        UserModel a = strict.user;
        strict.strictUser = true;
        new X509Authenticator(false, Configs::plain).authenticate(strict.context);
        assertFalse(strict.status == FlowStatus.SUCCESS);
        assertSame(a, strict.user);
        assertNull(strict.authNotes.get(X509Authenticator.METHOD_NOTE));
    }

    @Test
    void ownCertificateOnTheStepSignsIn() throws Exception {
        Flow f = step("alice");
        UserModel alice = f.user;
        new X509Authenticator(false, Configs::plain).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
        assertSame(alice, f.user);
        assertEquals("yubikey_cert", f.authNotes.get(X509Authenticator.METHOD_NOTE));
    }

    @Test
    void plainSignInWithNoUserSet() throws Exception {
        Flow f = step("mallory");
        f.user = null;
        new X509Authenticator(false, Configs::plain).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
        assertEquals("u-mallory", f.user.getId());
        assertEquals("yubikey_cert", f.authNotes.get(X509Authenticator.METHOD_NOTE));
    }

    @Test
    void completableOnlyWithTheirOwnCertificate() throws Exception {
        SigninConfig cfg = Configs.client(Configs.DEFAULT_METHODS, false, Configs.YUBIKEY_AND_CERT);
        Flow own = step("alice");
        own.completed("hwk");
        new TemplateAuthenticator(() -> cfg).authenticate(own.context);
        assertEquals(FlowStatus.FLOW_RESET, own.status, "her certificate completes the step");

        Flow other = step("mallory");
        other.completed("hwk");
        new TemplateAuthenticator(() -> cfg).authenticate(other.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, other.status, "another person's certificate isn't a candidate");
        assertEquals(TemplateAuthenticator.PAGE, other.page);

        Flow none = step((String) null);
        none.completed("hwk");
        new TemplateAuthenticator(() -> cfg).authenticate(none.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, none.status);

        // Her browser certificate is no YubiKey certificate: it can't complete a yubikey_cert step.
        Flow browser = step(TestCas.BROWSER.leaf("alice"));
        browser.completed("hwk");
        new TemplateAuthenticator(() -> cfg).authenticate(browser.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, browser.status);
    }

    @Test
    void browserCertCompletableWithOwnLeaf() {
        String any = "{\"op\": \"any\", \"items\": [\"browser_cert\"]}";
        SigninConfig cfg = Configs.client(X509AuthenticatorTest.ALL, false, any);
        Flow own = step(TestCas.BROWSER.leaf("alice"));
        own.completed("hwk");
        new TemplateAuthenticator(() -> cfg).authenticate(own.context);
        assertEquals(FlowStatus.FLOW_RESET, own.status, "her browser certificate completes the step");
        own.resetListener.run();
        assertEquals(java.util.Optional.of("browser_cert"), PcMethod.requested(own.context));

        Flow yubikey = step(TestCas.YUBIKEY.leaf("alice")); // a YubiKey leaf isn't a browser certificate
        yubikey.completed("hwk");
        new TemplateAuthenticator(() -> cfg).authenticate(yubikey.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, yubikey.status);

        Flow other = step(TestCas.BROWSER.leaf("mallory"));
        other.completed("hwk");
        new TemplateAuthenticator(() -> cfg).authenticate(other.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, other.status);
    }
}
