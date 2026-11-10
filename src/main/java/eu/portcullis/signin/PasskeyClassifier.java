package eu.portcullis.signin;

import com.fasterxml.jackson.databind.JsonNode;
import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import java.nio.ByteBuffer;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Passkey kinds (contract §8.1 "Passkey kinds", plan D14), decided from the
 * attestation against the Hub-published FIDO trust list.
 *
 * <ul>
 * <li>{@code security_key}: a {@code packed} / {@code tpm} /
 * {@code android-key} attestation whose {@code x5c} chains to that AAGUID's
 * published roots (webauthn4j's {@link DefaultCertPathTrustworthinessVerifier}
 * over a repository of exactly those roots), the leaf's AAGUID extension, when
 * present, equal to the authenticator data's AAGUID, the backup-eligible flag
 * 0, and the entry {@code {kind: security_key, status: certified}};</li>
 * <li>{@code passkey_device}: the same with {@code kind: passkey_device};</li>
 * <li>{@code passkey_synced}: everything else — and every failure. A
 * {@code fido-u2f} attestation has no AAGUID, so it is always synced.</li>
 * </ul>
 *
 * <p>Deterministic (the same attestation, list and time give the same kind) and
 * fail closed. The attestation signature is not checked here: Keycloak's
 * registration verified it (with the statement's own {@code x5c}) before the
 * row was stored.
 */
public final class PasskeyClassifier {
    private PasskeyClassifier() {}

    public static final String SYNCED = "passkey_synced";
    public static final String DEVICE = "passkey_device";
    public static final String SECURITY_KEY = "security_key";

    /** Keycloak credential types of the three kinds (contract §8.1 "Methods"). */
    public static final String TYPE_SYNCED = "webauthn-passwordless";
    public static final String TYPE_DEVICE = "portcullis-device-passkey";
    public static final String TYPE_SECURITY_KEY = "portcullis-security-key";

    /** The formats whose x5c can make a kind stronger than synced. */
    private static final Set<String> CERT_FORMATS = Set.of("packed", "tpm", "android-key");

    /** id-fido-gen-ce-aaguid. */
    static final String AAGUID_EXTENSION = "1.3.6.1.4.1.45724.1.1.4";

    private static final ObjectConverter OBJECTS = new ObjectConverter();
    private static final AttestationObjectConverter ATTESTATIONS = new AttestationObjectConverter(OBJECTS);

    /** Kinds weakest first: synced 0, device 1, security key 2; anything else -1. */
    public static int rank(String kind) {
        if (kind == null) {
            return -1;
        }
        return switch (kind) {
            case SYNCED -> 0;
            case DEVICE -> 1;
            case SECURITY_KEY -> 2;
            default -> -1;
        };
    }

    /** The credential type a kind is stored under. */
    public static String typeOf(String kind) {
        return switch (kind) {
            case SECURITY_KEY -> TYPE_SECURITY_KEY;
            case DEVICE -> TYPE_DEVICE;
            case SYNCED -> TYPE_SYNCED;
            default -> throw new IllegalArgumentException("not a passkey kind");
        };
    }

    /** The kind of a credential type (the stock {@code webauthn} counts as synced). */
    public static Optional<String> kindOfType(String type) {
        if (type == null) {
            return Optional.empty();
        }
        return switch (type) {
            case TYPE_SECURITY_KEY -> Optional.of(SECURITY_KEY);
            case TYPE_DEVICE -> Optional.of(DEVICE);
            case TYPE_SYNCED, "webauthn" -> Optional.of(SYNCED);
            default -> Optional.empty();
        };
    }

    /** The weaker of two kinds; a null cap is no cap. */
    static String atMost(String kind, String cap) {
        if (cap == null || rank(cap) < 0) {
            return kind;
        }
        return rank(kind) <= rank(cap) ? kind : cap;
    }

    /**
     * Reads a raw attestation object (the {@code attestationObject} the
     * browser posted): the format, the statement re-encoded as CBOR, the
     * authenticator data, its AAGUID and backup-eligible flag. Anything that
     * doesn't parse throws {@link IllegalArgumentException}.
     */
    public static StoredAttestation parse(byte[] attestationObject) {
        try {
            AttestationObject ao = ATTESTATIONS.convert(attestationObject);
            byte[] authData = ATTESTATIONS.extractAuthenticatorData(attestationObject);
            byte[] attStmt = ATTESTATIONS.extractAttestationStatement(attestationObject);
            AttestedCredentialData acd = ao.getAuthenticatorData().getAttestedCredentialData();
            if (acd == null || authData == null || attStmt == null) {
                throw new IllegalArgumentException("no attested credential data");
            }
            return new StoredAttestation(ao.getFormat(), attStmt, authData, acd.getAaguid().getValue(),
                    ao.getAuthenticatorData().isFlagBE());
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("not an attestation object", e);
        }
    }

    /** The credential id in the attestation's authenticator data. */
    public static byte[] credentialId(StoredAttestation a) {
        AttestedCredentialData acd = new AuthenticatorDataConverter(OBJECTS)
                .<RegistrationExtensionAuthenticatorOutput>convert(a.authenticatorData())
                .getAttestedCredentialData();
        if (acd == null || acd.getCredentialId() == null) {
            throw new IllegalArgumentException("no credential id");
        }
        return acd.getCredentialId();
    }

    /** The statement's x5c as standard base64 DER, leaf first (empty without one). */
    public static List<String> x5c(StoredAttestation a) {
        List<String> out = new ArrayList<>();
        try {
            if (rebuild(a).getAttestationStatement() instanceof CertificateBaseAttestationStatement s && s.getX5c() != null) {
                for (X509Certificate c : s.getX5c()) {
                    out.add(Base64.getEncoder().encodeToString(c.getEncoded()));
                }
            }
        } catch (Exception e) {
            return List.of();
        }
        return out;
    }

    /** The kind of a stored attestation against a trust list, at time now. */
    public static String kind(StoredAttestation a, SigninConfig cfg, Instant now) {
        if (a == null || cfg == null || now == null || a.fmt() == null || !CERT_FORMATS.contains(a.fmt())) {
            return SYNCED;
        }
        try {
            AttestationObject ao = rebuild(a);
            AuthenticatorData<RegistrationExtensionAuthenticatorOutput> ad = ao.getAuthenticatorData();
            AttestedCredentialData acd = ad.getAttestedCredentialData();
            if (acd == null || acd.getAaguid() == null || acd.getAaguid().getValue() == null) {
                return SYNCED;
            }
            UUID aaguid = acd.getAaguid().getValue();
            // The record's own fields must agree with the authenticator data.
            if (!aaguid.equals(a.aaguid()) || !a.fmt().equals(ao.getFormat())) {
                return SYNCED;
            }
            if (ad.isFlagBE() || a.backupEligible()) {
                return SYNCED;
            }
            SigninConfig.Trust t = cfg.authenticator(aaguid).orElse(null);
            if (t == null || !"certified".equals(t.status()) || rank(t.kind()) < 1) {
                return SYNCED;
            }
            AttestationStatement st = ao.getAttestationStatement();
            if (!(st instanceof CertificateBaseAttestationStatement s)) {
                return SYNCED;
            }
            AttestationCertificatePath x5c = s.getX5c();
            if (x5c == null || x5c.isEmpty()) {
                return SYNCED; // self attestation
            }
            if (!leafAaguidMatches(x5c.get(0), aaguid)) {
                return SYNCED;
            }
            DefaultCertPathTrustworthinessVerifier v = new DefaultCertPathTrustworthinessVerifier(new Roots(aaguid, t.roots()));
            v.verify(acd.getAaguid(), s, now); // throws when the chain doesn't verify
            return t.kind();
        } catch (RuntimeException e) {
            return SYNCED;
        }
    }

    /**
     * Reclassification (plan D14): upward only, never past the registration
     * cap; downward only for a {@code revoked} entry (to synced). A missing
     * entry or a chain that no longer verifies keeps the current kind.
     */
    public static String reclassify(String current, String cappedAt, StoredAttestation a, SigninConfig cfg, Instant now) {
        if (rank(current) < 0) {
            return SYNCED; // an unknown stored kind is the weakest
        }
        String next = kind(a, cfg, now);
        if (a != null && a.aaguid() != null && cfg != null) {
            Optional<SigninConfig.Trust> t = cfg.authenticator(a.aaguid());
            if (t.isPresent() && "revoked".equals(t.get().status())) {
                return SYNCED;
            }
        }
        if (rank(next) > rank(current)) {
            String capped = atMost(next, cappedAt);
            return rank(capped) > rank(current) ? capped : current;
        }
        return current;
    }

    /** The attestation object again, from the stored parts. */
    private static AttestationObject rebuild(StoredAttestation a) {
        CborConverter cbor = OBJECTS.getCborConverter();
        JsonNode stmt = cbor.readTree(a.attStmtCbor());
        Map<String, Object> ao = new LinkedHashMap<>();
        ao.put("fmt", a.fmt());
        ao.put("attStmt", stmt);
        ao.put("authData", a.authenticatorData());
        AttestationObject out = ATTESTATIONS.convert(cbor.writeValueAsBytes(ao));
        if (out == null) {
            throw new IllegalArgumentException("no attestation object");
        }
        return out;
    }

    /**
     * The leaf's id-fido-gen-ce-aaguid extension, when present, must be the
     * AAGUID. DER is canonical, so the only valid encoding of the extension
     * value (an OCTET STRING holding the 16 AAGUID bytes, wrapped in the
     * extnValue OCTET STRING the JDK returns) is compared byte for byte;
     * anything else is a mismatch.
     */
    static boolean leafAaguidMatches(X509Certificate leaf, UUID aaguid) {
        byte[] ext = leaf.getExtensionValue(AAGUID_EXTENSION);
        if (ext == null) {
            return true;
        }
        ByteBuffer want = ByteBuffer.allocate(20);
        want.put((byte) 0x04).put((byte) 0x12).put((byte) 0x04).put((byte) 0x10);
        want.putLong(aaguid.getMostSignificantBits()).putLong(aaguid.getLeastSignificantBits());
        return Arrays.equals(ext, want.array());
    }

    /** The published roots of one AAGUID; nothing for any other lookup (U2F key ids included). */
    private record Roots(UUID aaguid, List<X509Certificate> roots) implements TrustAnchorRepository {
        @Override
        public Set<TrustAnchor> find(AAGUID a) {
            if (a == null || !aaguid.equals(a.getValue())) {
                return Set.of();
            }
            Set<TrustAnchor> out = new LinkedHashSet<>();
            for (X509Certificate c : roots) {
                out.add(new TrustAnchor(c, null));
            }
            return out;
        }

        @Override
        public Set<TrustAnchor> find(byte[] attestationCertificateKeyIdentifier) {
            return Set.of();
        }
    }
}
