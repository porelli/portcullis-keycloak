package eu.portcullis.signin;

import static eu.portcullis.signin.Fixtures.YUBIKEY;
import static eu.portcullis.signin.Fixtures.config;
import static eu.portcullis.signin.Fixtures.entry;
import static eu.portcullis.signin.Fixtures.root3;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.portcullis.signin.store.PasskeyEntity;
import eu.portcullis.signin.store.PasskeyStore;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;

class ReclassifyTest {
    private static final Instant NOW = Instant.parse("2026-11-10T00:00:00Z");
    private static final String ID = "33333333-3333-3333-3333-333333333333";

    /** Keycloak's credential types, by credential id; ids in {@code failing} fail their lookup. */
    private static final class Types implements Reclassify.CredentialTypes {
        final Map<String, String> types = new HashMap<>();
        final Set<String> failing = new HashSet<>();

        @Override
        public Reclassify.Outcome setType(String userId, String credentialId, String type) {
            if (failing.contains(credentialId)) {
                return new Reclassify.Outcome.Failed("test");
            }
            if (!types.containsKey(credentialId)) {
                return new Reclassify.Outcome.Gone();
            }
            types.put(credentialId, type);
            return new Reclassify.Outcome.Applied("alice");
        }
    }

    private record World(TestDb db, RealmModel realm, Types types) {
        PasskeyEntity row() {
            db.em.clear();
            return new PasskeyStore(db.em).get(ID).orElseThrow();
        }

        int run(SigninConfig cfg) {
            return db.tx(em -> Reclassify.apply(new PasskeyStore(em), realm, cfg, types, NOW));
        }
    }

    /** A stored passkey of the given kind and cap, classified against serial 10, the realm at serial 10. */
    private static World world(TestDb db, StoredAttestation a, String kind, String cappedAt) {
        RealmModel realm = TestDb.realm("realm-1");
        Types types = new Types();
        types.types.put(ID, PasskeyClassifier.typeOf(kind));
        db.txRun(em -> {
            PasskeyStore s = new PasskeyStore(em);
            s.put(realm, TestDb.user("user-1", "alice"), PasskeyStoreTest.credential(ID), a, kind, cappedAt, 10, NOW);
            s.setLastSerial(realm, 10);
        });
        return new World(db, realm, types);
    }

    @Test
    void upwardWhenNewListVerifies() throws Exception {
        try (TestDb db = new TestDb()) {
            StoredAttestation a = Fixtures.packed(YUBIKEY);
            SigninConfig first = config(10);
            String kind = PasskeyClassifier.kind(a, first, NOW);
            assertEquals("passkey_synced", kind, "the first list lacks the AAGUID");
            World w = world(db, a, kind, null);

            assertEquals(1, w.run(config(11, false, entry(YUBIKEY, "security_key", "certified", root3()))));
            assertEquals("security_key", w.row().getKind());
            assertEquals(11, w.row().getMdsSerial());
            assertEquals("portcullis-security-key", w.types().types.get(ID));
            assertEquals(11, new PasskeyStore(db.em).lastSerial(w.realm()));
        }
    }

    @Test
    void missingEntryNeverDowngrades() throws Exception {
        try (TestDb db = new TestDb()) {
            World w = world(db, Fixtures.packed(YUBIKEY), "security_key", null);
            assertEquals(0, w.run(config(11)));
            assertEquals("security_key", w.row().getKind());
            assertEquals(11, w.row().getMdsSerial(), "classified again against 11");
            assertEquals("portcullis-security-key", w.types().types.get(ID));
            // A chain that no longer verifies (another root) doesn't downgrade either.
            assertEquals(0, w.run(config(12, false, entry(YUBIKEY, "security_key", "certified", Fixtures.root2()))));
            assertEquals("security_key", w.row().getKind());
            // Nor a weaker published kind.
            assertEquals(0, w.run(config(13, false, entry(YUBIKEY, "passkey_device", "certified", root3()))));
            assertEquals("security_key", w.row().getKind());
        }
    }

    @Test
    void revokedStatusDowngrades() throws Exception {
        try (TestDb db = new TestDb()) {
            World w = world(db, Fixtures.packed(YUBIKEY), "security_key", null);
            assertEquals(1, w.run(config(11, false, entry(YUBIKEY, "security_key", "revoked", root3()))));
            assertEquals("passkey_synced", w.row().getKind());
            assertEquals("webauthn-passwordless", w.types().types.get(ID));
        }
    }

    @Test
    void neverPastRegistrationCap() throws Exception {
        try (TestDb db = new TestDb()) {
            World w = world(db, Fixtures.packed(YUBIKEY), "passkey_synced", "passkey_synced");
            assertEquals(0, w.run(config(11, false, entry(YUBIKEY, "security_key", "certified", root3()))));
            assertEquals("passkey_synced", w.row().getKind());
            assertEquals("webauthn-passwordless", w.types().types.get(ID));
        }
        try (TestDb db = new TestDb()) {
            // A device cap stops a security key at device.
            World w = world(db, Fixtures.packed(YUBIKEY), "passkey_synced", "passkey_device");
            assertEquals(1, w.run(config(11, false, entry(YUBIKEY, "security_key", "certified", root3()))));
            assertEquals("passkey_device", w.row().getKind());
            assertEquals("portcullis-device-passkey", w.types().types.get(ID));
        }
    }

    @Test
    void sameSerialDoesNothing() throws Exception {
        try (TestDb db = new TestDb()) {
            World w = world(db, Fixtures.packed(YUBIKEY), "passkey_synced", null);
            long before = w.row().getClassifiedAt();
            SigninConfig verifies = config(10, false, entry(YUBIKEY, "security_key", "certified", root3()));
            assertEquals(0, w.run(verifies));
            assertEquals(0, w.run(config(9, false, entry(YUBIKEY, "security_key", "certified", root3()))), "an older serial neither");
            assertEquals(0, w.run(SigninConfig.DENY_ALL), "nor DENY_ALL");
            PasskeyEntity e = w.row();
            assertEquals("passkey_synced", e.getKind());
            assertEquals(10, e.getMdsSerial());
            assertEquals(before, e.getClassifiedAt(), "no row touched");
            assertEquals("webauthn-passwordless", w.types().types.get(ID));
            assertEquals(10, new PasskeyStore(db.em).lastSerial(w.realm()));
        }
    }

    @Test
    void goneCredentialIsLeftToTheSweep() throws Exception {
        try (TestDb db = new TestDb()) {
            World w = world(db, Fixtures.packed(YUBIKEY), "passkey_synced", null);
            w.types().types.clear(); // the credential was deleted meanwhile
            assertEquals(0, w.run(config(11, false, entry(YUBIKEY, "security_key", "certified", root3()))));
            assertEquals("passkey_synced", w.row().getKind());
            assertTrue(w.types().types.isEmpty());
            assertEquals(11, new PasskeyStore(db.em).lastSerial(w.realm()), "a confirmed-gone credential doesn't hold the serial back");
        }
    }

    @Test
    void failedLookupLeavesSerialUnapplied() throws Exception {
        try (TestDb db = new TestDb()) {
            // Row ID (YUBIKEY, synced) will fail its lookup; row REVOKED (OTHER, security key) gets revoked.
            World w = world(db, Fixtures.packed(YUBIKEY), "passkey_synced", null);
            String revokedId = "55555555-5555-5555-5555-555555555555";
            w.types().types.put(revokedId, "portcullis-security-key");
            db.txRun(em -> new PasskeyStore(em).put(w.realm(), TestDb.user("user-2", "bob"), PasskeyStoreTest.credential(revokedId),
                    Fixtures.packed(Fixtures.OTHER), "security_key", null, 10, NOW));
            SigninConfig next = config(11, false,
                    entry(YUBIKEY, "security_key", "certified", root3()),
                    entry(Fixtures.OTHER, "security_key", "revoked", root3()));
            w.types().failing.add(ID);

            // (a) the failed row is skipped, the revoked one is downgraded in the same pass.
            assertEquals(1, w.run(next));
            assertEquals("passkey_synced", w.row().getKind());
            assertEquals(10, w.row().getMdsSerial(), "the failed row keeps its serial");
            db.em.clear();
            PasskeyEntity revoked = new PasskeyStore(db.em).get(revokedId).orElseThrow();
            assertEquals("passkey_synced", revoked.getKind());
            assertEquals(11, revoked.getMdsSerial());
            assertEquals("webauthn-passwordless", w.types().types.get(revokedId));
            assertEquals(10, new PasskeyStore(db.em).lastSerial(w.realm()), "serial 11 held back");

            // (b) the lookup works again: the next run applies the failed row and the serial.
            w.types().failing.clear();
            assertEquals(1, w.run(next));
            assertEquals("security_key", w.row().getKind());
            assertEquals(11, w.row().getMdsSerial());
            assertEquals("portcullis-security-key", w.types().types.get(ID));
            assertEquals(11, new PasskeyStore(db.em).lastSerial(w.realm()));
        }
    }

    @Test
    void rowDecidedAgainstAnOlderSerialIsReclassified() throws Exception {
        try (TestDb db = new TestDb()) {
            // A registration that raced a list update: the realm applied 11, the row was decided against 10.
            World w = world(db, Fixtures.packed(YUBIKEY), "passkey_synced", null);
            db.txRun(em -> new PasskeyStore(em).setLastSerial(w.realm(), 11));
            assertEquals(1, w.run(config(11, false, entry(YUBIKEY, "security_key", "certified", root3()))));
            assertEquals("security_key", w.row().getKind());
            assertEquals(11, w.row().getMdsSerial());
        }
    }

    private static SigninConfig config(long serial) {
        return Fixtures.config(serial, false);
    }

    private static SigninConfig config(long serial, boolean addStronger, String... entries) {
        return Fixtures.config(serial, addStronger, entries);
    }
}
