package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.portcullis.signin.store.PasskeyEntity;
import eu.portcullis.signin.store.PasskeyStore;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

class PasskeyStoreTest {
    static CredentialModel credential(String id) {
        CredentialModel c = new CredentialModel();
        c.setId(id);
        c.setType(PasskeyClassifier.TYPE_SYNCED);
        return c;
    }

    private static int orphans(TestDb db, RealmModel r) {
        Integer n = db.tx(em -> new PasskeyStore(em).removeOrphans(r));
        return n;
    }

    @Test
    void attestationKeptWithCredential() throws Exception {
        try (TestDb db = new TestDb()) {
            RealmModel realm = TestDb.realm("realm-1");
            RealmModel otherRealm = TestDb.realm("realm-2");
            UserModel alice = TestDb.user("user-1", "alice");
            StoredAttestation a = Fixtures.packed(Fixtures.YUBIKEY);
            String id = "11111111-1111-1111-1111-111111111111";
            db.sql("INSERT INTO CREDENTIAL (ID) VALUES ('" + id + "')");
            Instant at = Instant.parse("2026-11-10T08:00:00Z");
            db.txRun(em -> new PasskeyStore(em).put(realm, alice, credential(id), a, "security_key", "security_key", 87, at));
            db.em.clear();

            PasskeyStore store = new PasskeyStore(db.em);
            PasskeyEntity e = store.get(id).orElseThrow();
            StoredAttestation back = PasskeyStore.attestation(e);
            assertEquals(a.fmt(), back.fmt());
            assertArrayEquals(a.attStmtCbor(), back.attStmtCbor());
            assertArrayEquals(a.authenticatorData(), back.authenticatorData());
            assertEquals(a.aaguid(), back.aaguid());
            assertEquals(a.backupEligible(), back.backupEligible());
            assertEquals(Fixtures.YUBIKEY.toString(), e.getAaguid());
            assertEquals(2, e.getX5c().split(",").length);
            assertEquals("realm-1", e.getRealmId());
            assertEquals("user-1", e.getUserId());
            assertEquals("security_key", e.getKind());
            assertEquals("security_key", e.getCappedAt());
            assertEquals(87, e.getMdsSerial());
            assertEquals(at.toEpochMilli(), e.getClassifiedAt());
            // The stored attestation still classifies the same.
            SigninConfig cfg = Fixtures.config(87, false, Fixtures.entry(Fixtures.YUBIKEY, "security_key", "certified", Fixtures.root3()));
            assertEquals("security_key", PasskeyClassifier.kind(back, cfg, at));
            assertEquals(1, store.all(realm).count());
            assertEquals(0, store.all(otherRealm).count());

            // The credential still exists: the sweep keeps the row.
            assertEquals(0, orphans(db, realm));
            assertTrue(store.get(id).isPresent());
            // Removing the credential removes the row.
            db.sql("DELETE FROM CREDENTIAL WHERE ID = '" + id + "'");
            assertEquals(0, orphans(db, otherRealm), "another realm's sweep leaves it");
            assertEquals(1, orphans(db, realm));
            assertTrue(store.get(id).isEmpty());

            // A federated user's credential counts as existing too.
            String fed = "22222222-2222-2222-2222-222222222222";
            db.sql("INSERT INTO FED_USER_CREDENTIAL (ID) VALUES ('" + fed + "')");
            db.txRun(em -> new PasskeyStore(em).put(realm, alice, credential(fed), Fixtures.none(Fixtures.YUBIKEY), "passkey_synced", null, 87, at));
            assertEquals(0, orphans(db, realm));
            PasskeyEntity f = store.get(fed).orElseThrow();
            assertNull(f.getX5c());
            assertNull(f.getCappedAt());
            assertTrue(store.credentialExists(fed));
            assertTrue(!store.credentialExists(id));
            // The provider-side removal.
            assertTrue(db.<Boolean>tx(em -> new PasskeyStore(em).remove(fed)));
            assertTrue(store.get(fed).isEmpty());

            // A deleted realm's rows and state go with it; another realm's stay.
            db.sql("INSERT INTO CREDENTIAL (ID) VALUES ('" + id + "')");
            String other = "44444444-4444-4444-4444-444444444444";
            db.txRun(em -> {
                PasskeyStore s = new PasskeyStore(em);
                s.put(realm, alice, credential(id), a, "security_key", null, 87, at);
                s.put(otherRealm, alice, credential(other), a, "security_key", null, 87, at);
                s.setLastSerial(realm, 87);
                s.setLastSerial(otherRealm, 87);
            });
            db.txRun(em -> new PasskeyStore(em).removeRealm("realm-1"));
            db.em.clear();
            assertTrue(store.get(id).isEmpty());
            assertEquals(-1, store.lastSerial(realm));
            assertTrue(store.get(other).isPresent());
            assertEquals(87, store.lastSerial(otherRealm));
            db.txRun(em -> new PasskeyStore(em).selfCheck());
        }
    }

    @Test
    void signinStateAndRefusals() throws Exception {
        try (TestDb db = new TestDb()) {
            RealmModel realm = TestDb.realm("realm-1");
            PasskeyStore store = new PasskeyStore(db.em);
            assertEquals(-1, store.lastSerial(realm));
            db.txRun(em -> new PasskeyStore(em).setLastSerial(realm, 4));
            assertEquals(4, store.lastSerial(realm));
            db.txRun(em -> new PasskeyStore(em).setLastSerial(realm, 5));
            assertEquals(5, store.lastSerial(realm));
            UserModel u = TestDb.user("u", "bob");
            StoredAttestation a = Fixtures.none(Fixtures.YUBIKEY);
            assertThrows(IllegalArgumentException.class, () -> store.put(realm, u, credential("x"), a, "webauthn", null, 1, Instant.now()));
            assertThrows(IllegalArgumentException.class, () -> store.put(realm, u, credential("x"), a, "passkey_synced", "password", 1, Instant.now()));
            assertThrows(IllegalArgumentException.class, () -> store.put(realm, u, credential(null), a, "passkey_synced", null, 1, Instant.now()));
        }
    }

    /** PORTCULLIS_IMP_NOTICE_SEEN (contract §8.1 "The notice"): from the changelog, never seen = NEVER, only ever forward. */
    @Test
    void noticeSeenOnlyForward() throws Exception {
        try (TestDb db = new TestDb()) {
            eu.portcullis.signin.store.NoticeSeenStore s = new eu.portcullis.signin.store.NoticeSeenStore(db.em);
            assertEquals(eu.portcullis.signin.store.NoticeSeenStore.NEVER, s.seenUntil("u-alice"));
            assertEquals(eu.portcullis.signin.store.NoticeSeenStore.NEVER, s.seenUntil(null));
            db.txRun(em -> new eu.portcullis.signin.store.NoticeSeenStore(em).advance("u-alice", 1_000L));
            db.em.clear();
            assertEquals(1_000L, s.seenUntil("u-alice"));
            db.txRun(em -> new eu.portcullis.signin.store.NoticeSeenStore(em).advance("u-alice", 500L));
            db.em.clear();
            assertEquals(1_000L, s.seenUntil("u-alice"), "never back");
            db.txRun(em -> new eu.portcullis.signin.store.NoticeSeenStore(em).advance("u-alice", 2_000L));
            db.em.clear();
            assertEquals(2_000L, s.seenUntil("u-alice"));
            assertEquals(eu.portcullis.signin.store.NoticeSeenStore.NEVER, s.seenUntil("u-bob"));
            // A user id longer than a UUID (a federated id) fits.
            String fed = "f:" + "0".repeat(36) + ":" + "alice".repeat(10);
            db.txRun(em -> new eu.portcullis.signin.store.NoticeSeenStore(em).advance(fed, 7L));
            db.em.clear();
            assertEquals(7L, s.seenUntil(fed));
            db.txRun(em -> new PasskeyStore(em).selfCheck());
        }
    }

    /**
     * M2: two first Continues racing (no row yet). The loser's insert hits the
     * primary key at commit; advanceInOwnTransaction runs it again, which
     * finds the winner's row and moves it forward. Never an exception.
     */
    @Test
    void noticeSeenFirstInsertRace() throws Exception {
        try (TestDb db = new TestDb()) {
            int[] attempts = {0};
            eu.portcullis.signin.store.NoticeSeenStore.Tx racing = job -> {
                jakarta.persistence.EntityManager mine = db.newEntityManager();
                try {
                    mine.getTransaction().begin();
                    job.accept(mine); // finds no row, persists
                    if (attempts[0]++ == 0) {
                        // The other Continue commits its row first.
                        db.txRun(em -> new eu.portcullis.signin.store.NoticeSeenStore(em).advance("u-alice", 1_000L));
                    }
                    mine.getTransaction().commit();
                } catch (RuntimeException e) {
                    if (mine.getTransaction().isActive()) {
                        mine.getTransaction().rollback();
                    }
                    throw e;
                } finally {
                    mine.close();
                }
            };
            assertTrue(eu.portcullis.signin.store.NoticeSeenStore.advanceInOwnTransaction(racing, "u-alice", 2_000L));
            assertEquals(2, attempts[0], "the loser ran again");
            db.em.clear();
            assertEquals(2_000L, new eu.portcullis.signin.store.NoticeSeenStore(db.em).seenUntil("u-alice"));

            // The retry with a lower value keeps the winner's (never back).
            attempts[0] = 0;
            db.txRun(em -> em.createQuery("delete from PortcullisImpNoticeSeen").executeUpdate());
            db.em.clear();
            eu.portcullis.signin.store.NoticeSeenStore.Tx racingHigher = job -> {
                jakarta.persistence.EntityManager mine = db.newEntityManager();
                try {
                    mine.getTransaction().begin();
                    job.accept(mine);
                    if (attempts[0]++ == 0) {
                        db.txRun(em -> new eu.portcullis.signin.store.NoticeSeenStore(em).advance("u-alice", 9_000L));
                    }
                    mine.getTransaction().commit();
                } catch (RuntimeException e) {
                    if (mine.getTransaction().isActive()) {
                        mine.getTransaction().rollback();
                    }
                    throw e;
                } finally {
                    mine.close();
                }
            };
            assertTrue(eu.portcullis.signin.store.NoticeSeenStore.advanceInOwnTransaction(racingHigher, "u-alice", 2_000L));
            db.em.clear();
            assertEquals(9_000L, new eu.portcullis.signin.store.NoticeSeenStore(db.em).seenUntil("u-alice"));

            // Failing every time: false, never an exception (the Continue still completes).
            assertFalse(eu.portcullis.signin.store.NoticeSeenStore.advanceInOwnTransaction(job -> {
                throw new jakarta.persistence.PersistenceException("down");
            }, "u-alice", 3_000L));
        }
    }
}
