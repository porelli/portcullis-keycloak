package eu.portcullis.signin;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.test.AttestationCertificateBuilder;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.test.authenticator.webauthn.WebAuthnModelAuthenticator;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;

/**
 * Test attestations and trust lists. Attestations are webauthn4j-test's
 * emulators (AAGUID zero) or built from webauthn4j-test's 3-tier test CA
 * (an attestation leaf issued by its intermediate CA) for chosen AAGUIDs.
 */
final class Fixtures {
    private Fixtures() {}

    static final UUID YUBIKEY = UUID.fromString("cb69481e-8ff7-4039-93ec-0a2729a154a8");
    static final UUID OTHER = UUID.fromString("ee882879-721c-4913-9775-3dfcce97072a");
    static final UUID ZERO = new UUID(0, 0);

    private static final ObjectConverter OBJECTS = new ObjectConverter();
    static final byte BIT_UP = AuthenticatorData.BIT_UP;
    static final byte BIT_UV = AuthenticatorData.BIT_UV;
    static final byte BIT_AT = AuthenticatorData.BIT_AT;
    static final byte BIT_BE = AuthenticatorData.BIT_BE;
    static final byte BIT_BS = AuthenticatorData.BIT_BS;

    static String b64(X509Certificate c) {
        try {
            return java.util.Base64.getEncoder().encodeToString(c.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The root the built and emulated attestations chain to. */
    static String root3() {
        return b64(TestAttestationUtil.load3tierTestRootCACertificate());
    }

    /** Another, unrelated root. */
    static String root2() {
        return b64(TestAttestationUtil.load2tierTestRootCACertificate());
    }

    static String entry(UUID aaguid, String kind, String status, String root) {
        return "\"%s\": {\"kind\": \"%s\", \"status\": \"%s\", \"roots\": [\"%s\"]}".formatted(aaguid, kind, status, root);
    }

    /** A signin-keycloak.json with the four default methods on and these trust-list entries. */
    static SigninConfig config(long serial, boolean addStronger, String... entries) {
        StringJoiner j = new StringJoiner(", ");
        for (String e : entries) {
            j.add(e);
        }
        String body = """
            {"version": 1, "methods": ["passkey_device", "passkey_synced", "security_key", "yubikey_cert"],
             "add_stronger": %s, "templates": {}, "clients": {}, "authenticators": {%s},
             "mds": {"serial": %d, "next_update": "2026-12-01T00:00:00Z"}}
            """.formatted(addStronger, j, serial);
        try {
            SigninConfig c = SigninConfig.parse(body.getBytes(StandardCharsets.UTF_8));
            if (c == SigninConfig.DENY_ALL) {
                throw new IllegalStateException("test config refused");
            }
            return c;
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A real registration from a webauthn4j-test emulator. */
    static StoredAttestation emulated(WebAuthnModelAuthenticator authenticator) {
        return create(EmulatorUtil.createClientPlatform(authenticator));
    }

    /** A real U2F registration (webauthn4j-test's FIDO U2F emulator). */
    static StoredAttestation emulatedU2F() {
        return create(EmulatorUtil.createClientPlatform(EmulatorUtil.FIDO_U2F_AUTHENTICATOR));
    }

    private static StoredAttestation create(com.webauthn4j.test.client.ClientPlatform platform) {
        PublicKeyCredentialCreationOptions o = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity("example.com", "example.com"),
                new PublicKeyCredentialUserEntity(new byte[] {1, 2, 3}, "alice", "alice"),
                new DefaultChallenge(),
                List.of(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)),
                null, null,
                new com.webauthn4j.data.AuthenticatorSelectionCriteria(null,
                        com.webauthn4j.data.ResidentKeyRequirement.DISCOURAGED,
                        com.webauthn4j.data.UserVerificationRequirement.PREFERRED),
                AttestationConveyancePreference.DIRECT, null);
        byte[] ao = platform.create(o).getResponse().getAttestationObject();
        return PasskeyClassifier.parse(ao);
    }

    static StoredAttestation emulatedPacked() {
        return emulated(EmulatorUtil.PACKED_AUTHENTICATOR);
    }

    private static KeyPair ecKey() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] bytes(UUID u) {
        return ByteBuffer.allocate(16).putLong(u.getMostSignificantBits()).putLong(u.getLeastSignificantBits()).array();
    }

    /** An attestation leaf issued by the 3-tier test intermediate CA, with an AAGUID extension when leafAaguid isn't null. */
    static X509Certificate leaf(KeyPair key, UUID leafAaguid) {
        AttestationCertificateBuilder b = new AttestationCertificateBuilder(
                TestAttestationUtil.load3tierTestIntermediateCACertificate(),
                new X500Principal("CN=Test Authenticator, OU=Authenticator Attestation, O=Portcullis Test, C=US"),
                key.getPublic());
        if (leafAaguid != null) {
            b.addExtension(new ASN1ObjectIdentifier(PasskeyClassifier.AAGUID_EXTENSION), false, new DEROctetString(bytes(leafAaguid)));
        }
        return b.build(TestAttestationUtil.load3tierTestIntermediateCAPrivateKey());
    }

    private static StoredAttestation build(UUID aaguid, byte flags, AttestationStatement stmt) {
        KeyPair credential = ecKey();
        AttestedCredentialData acd = new AttestedCredentialData(new AAGUID(aaguid), new byte[] {9, 8, 7, 6},
                EC2COSEKey.create((ECPublicKey) credential.getPublic(), COSEAlgorithmIdentifier.ES256));
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> ad =
                new AuthenticatorData<>(new byte[32], (byte) (flags | BIT_AT), 0, acd);
        byte[] ao = new AttestationObjectConverter(OBJECTS).convertToBytes(new AttestationObject(ad, stmt));
        return PasskeyClassifier.parse(ao);
    }

    /**
     * A packed attestation (the signature is a placeholder: the classifier
     * checks the chain, Keycloak checks signatures at registration).
     */
    static StoredAttestation packed(UUID aaguid, UUID leafAaguid, byte flags) {
        KeyPair attestationKey = ecKey();
        List<X509Certificate> cas = new ArrayList<>();
        cas.add(TestAttestationUtil.load3tierTestIntermediateCACertificate());
        AttestationCertificatePath x5c = new AttestationCertificatePath(leaf(attestationKey, leafAaguid), cas);
        return build(aaguid, flags, new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[64], x5c));
    }

    static StoredAttestation packed(UUID aaguid) {
        return packed(aaguid, aaguid, (byte) (BIT_UP | BIT_UV));
    }

    /** Packed self attestation: no x5c. */
    static StoredAttestation self(UUID aaguid) {
        return build(aaguid, (byte) (BIT_UP | BIT_UV), new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[64], null));
    }

    static StoredAttestation none(UUID aaguid) {
        return build(aaguid, (byte) (BIT_UP | BIT_UV), new NoneAttestationStatement());
    }
}
