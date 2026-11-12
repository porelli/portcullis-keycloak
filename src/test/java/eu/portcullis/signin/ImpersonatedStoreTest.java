package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.portcullis.signin.store.ImpersonatedStore;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;

/** PORTCULLIS_IMPERSONATED (contract §8.1 "Ending"): the changelog's table, marks per realm, a racing start kept. */
class ImpersonatedStoreTest {
    @Test
    void marksPerRealm() throws Exception {
        try (TestDb db = new TestDb()) {
            RealmModel realm = TestDb.realm("realm-1");
            RealmModel other = TestDb.realm("realm-2");
            Instant t = Instant.parse("2026-11-12T14:00:00Z");
            db.txRun(em -> {
                ImpersonatedStore s = new ImpersonatedStore(em);
                s.mark(realm, TestDb.user("u-alice", "alice"), t);
                s.mark(other, TestDb.user("u-bob", "bob"), t);
            });
            db.em.clear();
            ImpersonatedStore s = new ImpersonatedStore(db.em);
            assertEquals(List.of(new ImpersonatedStore.Mark("u-alice", "alice", t.getEpochSecond())), s.marked(realm));

            // A second start refreshes the mark; an unmark decided before it keeps the row.
            db.txRun(em -> new ImpersonatedStore(em).mark(realm, TestDb.user("u-alice", "alice"), t.plusSeconds(100)));
            db.txRun(em -> new ImpersonatedStore(em).unmark("u-alice", t.getEpochSecond()));
            db.em.clear();
            assertEquals(1, s.marked(realm).size());
            db.txRun(em -> new ImpersonatedStore(em).unmark("u-alice", t.plusSeconds(100).getEpochSecond()));
            db.em.clear();
            assertTrue(s.marked(realm).isEmpty());

            db.txRun(em -> new ImpersonatedStore(em).removeRealm("realm-2"));
            db.em.clear();
            assertTrue(s.marked(other).isEmpty());
            db.txRun(em -> new eu.portcullis.signin.store.PasskeyStore(em).selfCheck());
        }
    }
}
