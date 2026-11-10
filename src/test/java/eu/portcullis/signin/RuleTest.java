package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class RuleTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    private static JsonNode vectors() throws IOException {
        try (InputStream in = RuleTest.class.getResourceAsStream("/signin_vectors.json")) {
            assertNotNull(in, "signin_vectors.json on the test classpath");
            return JSON.readTree(in);
        }
    }

    private static Set<Set<String>> setOfSets(Iterable<? extends Iterable<String>> alts) {
        Set<Set<String>> out = new HashSet<>();
        for (Iterable<String> a : alts) {
            Set<String> s = new HashSet<>();
            a.forEach(s::add);
            out.add(s);
        }
        return out;
    }

    /**
     * Every case of the Hub's shared vectors (portcullis-hub
     * internal/signin/testdata/vectors.json): an evaluated case's compiled
     * rule parses, meets "have" (amr values through the method table) as
     * "satisfied" says and has exactly the listed alternatives (a set of
     * sets); a "reject" case's compiled rule is refused. Cases with "error"
     * have no compiled rule (compiling is the Hub's).
     */
    @Test
    void sharedVectors() throws IOException {
        JsonNode f = vectors();
        assertEquals(1, f.get("version").asInt());
        assertFalse(f.get("note").asText().isEmpty());
        int evaluated = 0, rejects = 0, errors = 0;
        boolean sawInv = false;
        for (JsonNode c : f.get("cases")) {
            String name = c.get("name").asText();
            if (c.path("reject").asBoolean(false)) {
                rejects++;
                assertThrows(IllegalArgumentException.class, () -> Rule.parse(c.get("compiled")), name);
                continue;
            }
            if (c.has("error")) {
                errors++;
                assertFalse(c.has("compiled"), name);
                continue;
            }
            evaluated++;
            Rule r = Rule.parse(c.get("compiled"));
            Set<String> have = new HashSet<>();
            for (JsonNode a : c.get("have")) {
                if (a.asText().equals("inv")) {
                    sawInv = true;
                }
                Methods.forAmr(a.asText()).ifPresent(have::add);
            }
            assertEquals(c.get("satisfied").asBoolean(), r.satisfiedBy(have), name + ": satisfiedBy " + have);
            Set<Set<String>> want = new HashSet<>();
            for (JsonNode alt : c.get("alternatives")) {
                Set<String> s = new HashSet<>();
                alt.forEach(m -> s.add(m.asText()));
                want.add(s);
            }
            List<Set<String>> got = r.alternatives();
            assertEquals(want, setOfSets(got), name + ": alternatives");
            assertEquals(want.size(), got.size(), name + ": alternatives listed once each");
            // satisfiedBy agrees with the alternatives.
            boolean met = got.stream().anyMatch(have::containsAll);
            assertEquals(c.get("satisfied").asBoolean(), met, name + ": alternatives say met=" + met);
        }
        assertTrue(evaluated >= 25, evaluated + " evaluated cases");
        assertTrue(rejects >= 5, rejects + " reject cases");
        assertTrue(errors >= 1, errors + " error cases");
        assertTrue(sawInv, "a case with \"have\": [\"inv\"]");
    }

    @Test
    void rejectsUnknownLeafAndDepth() throws IOException {
        String[] bad = {
            // an unknown leaf (the stock amr name, not a method id)
            "{\"op\":\"any\",\"items\":[\"webauthn\"]}",
            // compiled depth 5
            "{\"op\":\"any\",\"items\":[{\"op\":\"all\",\"items\":[{\"op\":\"any\",\"items\":[{\"op\":\"all\",\"items\":[{\"op\":\"any\",\"items\":[\"security_key\"]}]}]}]}]}",
            // families are compiled away
            "{\"op\":\"any\",\"items\":[\"family:passkey\"]}",
            // amr values aren't leaves
            "{\"op\":\"any\",\"items\":[\"hwk\"]}",
            "{\"op\":\"any\",\"items\":[\"inv\"]}",
            // shape
            "\"security_key\"",
            "{\"op\":\"none\",\"items\":[\"security_key\"]}",
            "{\"op\":\"any\"}",
            "{\"items\":[\"security_key\"]}",
            "{\"op\":\"any\",\"items\":[]}",
            "{\"op\":\"any\",\"items\":\"security_key\"}",
            "{\"op\":\"any\",\"items\":[\"security_key\"],\"x\":1}",
            "{\"op\":\"any\",\"items\":[\"\"]}",
            "{\"op\":\"any\",\"items\":[null]}",
            "{\"op\":\"any\",\"items\":[1]}",
            "{\"op\":\"any\",\"items\":[[\"security_key\"]]}",
            "{\"op\":\"ANY\",\"items\":[\"security_key\"]}",
            "{\"op\":1,\"items\":[\"security_key\"]}",
            // nine items in one group
            "{\"op\":\"any\",\"items\":[\"password\",\"password\",\"password\",\"password\",\"password\",\"password\",\"password\",\"password\",\"password\"]}",
            "null",
        };
        for (String b : bad) {
            JsonNode n = JSON.readTree(b);
            assertThrows(IllegalArgumentException.class, () -> Rule.parse(n), b);
        }
        assertThrows(IllegalArgumentException.class, () -> Rule.parse(null));

        // Depth 4 and 48 leaves are the limits, still accepted.
        Rule.parse(JSON.readTree("{\"op\":\"any\",\"items\":[{\"op\":\"all\",\"items\":[{\"op\":\"any\",\"items\":[{\"op\":\"all\",\"items\":[\"security_key\"]}]}]}]}"));
        StringBuilder sb = new StringBuilder("{\"op\":\"any\",\"items\":[");
        for (int g = 0; g < 8; g++) {
            sb.append(g > 0 ? "," : "").append("{\"op\":\"any\",\"items\":[");
            for (int i = 0; i < 6; i++) {
                sb.append(i > 0 ? "," : "").append("\"security_key\"");
            }
            sb.append("]}");
        }
        Rule r48 = Rule.parse(JSON.readTree(sb.append("]}").toString()));
        assertEquals(List.of(Set.of("security_key")), r48.alternatives());
    }

    @Test
    void unmeetableMeetsNothing() {
        assertFalse(Rule.UNMEETABLE.satisfiedBy(Set.of("password", "passkey_synced", "browser_cert",
                "passkey_device", "security_key", "yubikey_cert")));
        assertTrue(Rule.UNMEETABLE.alternatives().isEmpty());
    }

    @Test
    void methodTable() {
        assertEquals("password", Methods.forAmr("pwd").orElseThrow());
        assertEquals("passkey_synced", Methods.forAmr("spk").orElseThrow());
        assertEquals("browser_cert", Methods.forAmr("file").orElseThrow());
        assertEquals("passkey_device", Methods.forAmr("dpk").orElseThrow());
        assertEquals("security_key", Methods.forAmr("hwk").orElseThrow());
        assertEquals("yubikey_cert", Methods.forAmr("mtls").orElseThrow());
        for (String a : new String[] {"inv", "HWK", "webauthn", "otp", "", "security_key"}) {
            assertTrue(Methods.forAmr(a).isEmpty(), a);
        }
        assertTrue(Methods.forAmr(null).isEmpty());
        assertEquals(10, Methods.tenths("password"));
        assertEquals(25, Methods.tenths("passkey_synced"));
        assertEquals(25, Methods.tenths("browser_cert"));
        assertEquals(30, Methods.tenths("passkey_device"));
        assertEquals(35, Methods.tenths("security_key"));
        assertEquals(40, Methods.tenths("yubikey_cert"));
        assertThrows(IllegalArgumentException.class, () -> Methods.tenths("family:passkey"));
        assertThrows(IllegalArgumentException.class, () -> Methods.tenths("inv"));
    }
}
