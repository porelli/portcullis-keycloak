package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.webauthn4j.test.AttestationCertificateBuilder;
import com.webauthn4j.test.TestAttestationUtil;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
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

    static X509Certificate certificate(String cn) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair key = g.generateKeyPair();
        return new AttestationCertificateBuilder(TestAttestationUtil.load3tierTestIntermediateCACertificate(),
                new X500Principal("CN=" + cn + ", O=Portcullis Test"), key.getPublic())
                .build(TestAttestationUtil.load3tierTestIntermediateCAPrivateKey());
    }

    static final Map<String, String> X509 = Map.of(
            AbstractX509ClientCertificateAuthenticator.MAPPING_SOURCE_SELECTION, AbstractX509ClientCertificateAuthenticator.MAPPING_SOURCE_CERT_SUBJECTDN_CN,
            AbstractX509ClientCertificateAuthenticator.USER_MAPPER_SELECTION, AbstractX509ClientCertificateAuthenticator.USERNAME_EMAIL_MAPPER,
            AbstractX509ClientCertificateAuthenticator.CONFIRMATION_PAGE_DISALLOWED, "true",
            "default.reference.value", "mtls");

    /** alice signed in with her security key; mallory exists too; the request presents cn's certificate. */
    static Flow step(String cn) throws Exception {
        Flow f = new Flow();
        f.user = f.person("u-alice", "alice").passkey(PasskeyClassifier.TYPE_SECURITY_KEY, Flow.bytes("k")).model;
        f.person("u-mallory", "mallory");
        f.certificates = cn == null ? null : new X509Certificate[] {certificate(cn)};
        f.config(new HashMap<>(X509));
        // The flow holds portcullis-x509 in a sub-flow, with this config.
        AuthenticationExecutionModel sub = new AuthenticationExecutionModel();
        sub.setAuthenticatorFlow(true);
        sub.setFlowId("flow-signin");
        AuthenticationExecutionModel x509 = new AuthenticationExecutionModel();
        x509.setAuthenticator(X509AuthenticatorFactory.PROVIDER_ID);
        x509.setAuthenticatorConfig("cfg-x509");
        AuthenticatorConfigModel c = new AuthenticatorConfigModel();
        c.setId("cfg-x509");
        c.setConfig(new HashMap<>(X509));
        f.configs.put("cfg-x509", c);
        f.flows.put("flow-top", List.of(sub));
        f.flows.put("flow-signin", List.of(x509));
        return f;
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

        Flow none = step(null);
        none.completed("hwk");
        new TemplateAuthenticator(() -> cfg).authenticate(none.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, none.status);
    }
}
