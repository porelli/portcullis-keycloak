package eu.portcullis.signin;

import java.util.UUID;

/**
 * A passkey's attestation as the extension keeps it for the credential's
 * whole life (contract §8.1 "Passkey kinds", plan D5 / D14): the attestation
 * format, the attestation statement as CBOR, the authenticator data, and the
 * two values read from the authenticator data (AAGUID, backup-eligible flag).
 *
 * <p>{@link PasskeyClassifier} re-reads the authenticator data and refuses
 * (synced) a record whose AAGUID or flag disagrees with it.
 */
public record StoredAttestation(String fmt, byte[] attStmtCbor, byte[] authenticatorData, UUID aaguid, boolean backupEligible) {}
