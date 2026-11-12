package eu.portcullis.signin;

import com.webauthn4j.test.AttestationCertificateBuilder;
import com.webauthn4j.test.TestAttestationUtil;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import javax.security.auth.x500.X500Principal;

/**
 * The two internal CAs of the tests, like core's {@code pki_int} (YubiKey
 * certificates) and {@code pki_file} (browser certificates): both signed by
 * webauthn4j-test's 3-tier test root, each with its own key, and leaves
 * (CN = a username) issued by either.
 */
final class TestCas {
    private TestCas() {}

    /** A CA: its certificate and key. */
    record Ca(X509Certificate cert, KeyPair key) {
        /** A leaf for username cn, issued (named and signed) by this CA. */
        X509Certificate leaf(String cn) {
            return issue(cert, key, cn);
        }

        /** Its certificate as a PEM file in dir. */
        Path pem(Path dir, String name) throws Exception {
            Path p = dir.resolve(name);
            Files.writeString(p, TestCas.pem(cert), StandardCharsets.US_ASCII);
            return p;
        }
    }

    static final Ca YUBIKEY = ca("CN=example.com YubiKey Certificate CA, O=Portcullis Test");
    static final Ca BROWSER = ca("CN=example.com Browser Certificate CA, O=Portcullis Test");

    static KeyPair keyPair() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Ca ca(String subject) {
        KeyPair key = keyPair();
        AttestationCertificateBuilder b = new AttestationCertificateBuilder(TestAttestationUtil.load3tierTestRootCACertificate(),
                new X500Principal(subject), key.getPublic());
        b.addBasicConstraintsExtension();
        return new Ca(b.build(TestAttestationUtil.load3tierTestRootCAPrivateKey()), key);
    }

    /** A leaf for cn named as issued by issuer, signed with signer's private key. */
    static X509Certificate issue(X509Certificate issuer, KeyPair signer, String cn) {
        return new AttestationCertificateBuilder(issuer, new X500Principal("CN=" + cn + ", O=Portcullis Test"), keyPair().getPublic())
                .build(signer.getPrivate());
    }

    /** A self-signed certificate with this subject (its own name as issuer, signed by its own key). */
    static X509Certificate selfSigned(String subject) {
        KeyPair key = keyPair();
        // A throwaway certificate with that subject, so the builder names it as the issuer.
        X509Certificate named = new AttestationCertificateBuilder(TestAttestationUtil.load3tierTestRootCACertificate(),
                new X500Principal(subject), key.getPublic()).build(TestAttestationUtil.load3tierTestRootCAPrivateKey());
        return new AttestationCertificateBuilder(named, new X500Principal(subject), key.getPublic()).build(key.getPrivate());
    }

    static String pem(X509Certificate c) {
        try {
            return "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(c.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
