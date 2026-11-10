package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.webauthn4j.test.TestAttestationUtil;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SigninConfigTest {
    private static final String AAGUID = "cb69481e-8ff7-4039-93ec-0a2729a154a8";

    private static String root() {
        try {
            return Base64.getEncoder().encodeToString(TestAttestationUtil.load3tierTestRootCACertificate().getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The contract §8.1 example, with a real root certificate. */
    static String valid() {
        return """
            {
              "version": 1,
              "methods": ["passkey_device", "passkey_synced", "security_key", "yubikey_cert"],
              "add_stronger": false,
              "templates": {
                "standard": {"op": "any", "items": [
                  {"op": "any", "items": ["passkey_synced", "passkey_device", "security_key"]},
                  {"op": "any", "items": ["yubikey_cert"]}
                ]},
                "strong": {"op": "any", "items": ["security_key", "yubikey_cert"]}
              },
              "clients": {
                "nextcloud": {"template": "standard", "name": "Nextcloud"},
                "nextcloud-office": {"template": "strong", "name": "Nextcloud · Office"}
              },
              "authenticators": {
                "%s": {"kind": "security_key", "status": "certified", "roots": ["%s"]}
              },
              "mds": {"serial": 87, "next_update": "2026-12-01T00:00:00Z"}
            }
            """.formatted(AAGUID, root());
    }

    private static Path write(Path dir, String name, String body) throws Exception {
        Path p = dir.resolve(name);
        Files.writeString(p, body, StandardCharsets.UTF_8);
        return p;
    }

    private static void assertDenyAll(SigninConfig c, String why) {
        assertSame(SigninConfig.DENY_ALL, c, why);
        for (String m : new String[] {"password", "passkey_synced", "browser_cert", "passkey_device", "security_key", "yubikey_cert"}) {
            assertFalse(c.on(m), why + ": " + m + " on");
        }
        assertFalse(c.addStronger(), why);
        assertEquals(-1, c.mdsSerial(), why);
        // Every client fails, listed or not: never "unlisted, left to group-gate".
        for (String client : new String[] {"nextcloud", "unlisted", "account-console"}) {
            Rule r = c.templateForClient(client).orElseThrow();
            assertFalse(r.satisfiedBy(Set.of("password", "passkey_synced", "passkey_device", "security_key", "yubikey_cert")), why);
        }
        assertTrue(c.authenticator(UUID.fromString(AAGUID)).isEmpty(), why);
    }

    @Test
    void validFileLoads(@TempDir Path dir) throws Exception {
        SigninConfig c = SigninConfig.load(write(dir, "ok.json", valid()));
        assertNotSame(SigninConfig.DENY_ALL, c);
        assertTrue(c.on("security_key"));
        assertTrue(c.on("passkey_synced"));
        assertFalse(c.on("password"));
        assertFalse(c.on("browser_cert"));
        assertFalse(c.on("inv"));
        assertFalse(c.on(null));
        assertFalse(c.addStronger());
        assertEquals(87, c.mdsSerial());
        assertEquals(Instant.parse("2026-12-01T00:00:00Z"), c.mdsNextUpdate());
        Rule strong = c.templateForClient("nextcloud-office").orElseThrow();
        assertTrue(strong.satisfiedBy(Set.of("security_key")));
        assertFalse(strong.satisfiedBy(Set.of("passkey_device")));
        assertTrue(c.templateForClient("nextcloud").orElseThrow().satisfiedBy(Set.of("passkey_synced")));
        assertTrue(c.templateForClient("unlisted").isEmpty(), "an unlisted client is left to group-gate");
        assertEquals("Nextcloud · Office", c.clientName("nextcloud-office").orElseThrow());
        assertTrue(c.clientName("unlisted").isEmpty());
        SigninConfig.Trust t = c.authenticator(UUID.fromString(AAGUID)).orElseThrow();
        assertEquals("security_key", t.kind());
        assertEquals("certified", t.status());
        assertEquals(1, t.roots().size());
        assertEquals(TestAttestationUtil.load3tierTestRootCACertificate(), t.roots().get(0));
        assertTrue(c.authenticator(UUID.randomUUID()).isEmpty());
        assertTrue(c.authenticator(null).isEmpty());

        // The before-the-first-BLOB shape, nothing listed.
        String empty = """
            {"version":1,"methods":[],"add_stronger":true,"templates":{},"clients":{},
             "authenticators":{},"mds":{"serial":0,"next_update":"0001-01-01T00:00:00Z"}}""";
        SigninConfig e = SigninConfig.load(write(dir, "empty.json", empty));
        assertNotSame(SigninConfig.DENY_ALL, e);
        assertTrue(e.addStronger());
        assertEquals(0, e.mdsSerial());
        assertTrue(e.templateForClient("x").isEmpty());
    }

    @Test
    void invalidOrMissingFileIsDenyAll(@TempDir Path dir) throws Exception {
        String ok = valid();
        String[][] bad = {
            {"unknown key", ok.replace("\"add_stronger\": false,", "\"add_stronger\": false, \"extra\": 1,")},
            {"unknown key in a client", ok.replace("\"name\": \"Nextcloud\"}", "\"name\": \"Nextcloud\", \"x\": 1}")},
            {"unknown key in an authenticator", ok.replace("\"status\": \"certified\",", "\"status\": \"certified\", \"x\": 1,")},
            {"unknown key in mds", ok.replace("\"serial\": 87,", "\"serial\": 87, \"x\": 1,")},
            {"version 2", ok.replace("\"version\": 1", "\"version\": 2")},
            {"version as a string", ok.replace("\"version\": 1", "\"version\": \"1\"")},
            {"version as a float", ok.replace("\"version\": 1", "\"version\": 1.0")},
            {"bad JSON", ok.substring(0, ok.length() / 2)},
            {"trailing data", ok + "{}"},
            {"duplicate key", ok.replace("\"add_stronger\": false,", "\"add_stronger\": false, \"add_stronger\": true,")},
            {"not an object", "[]"},
            {"empty", ""},
            {"missing field", ok.replace("\"add_stronger\": false,", "")},
            {"missing mds", ok.replaceAll(",\\s*\"mds\": \\{[^}]*\\}", "")},
            {"null field", ok.replace("\"add_stronger\": false", "\"add_stronger\": null")},
            {"boolean as a string", ok.replace("\"add_stronger\": false", "\"add_stronger\": \"false\"")},
            {"boolean as a number", ok.replace("\"add_stronger\": false", "\"add_stronger\": 0")},
            {"unknown method", ok.replace("\"passkey_device\", \"passkey_synced\"", "\"passkey_device\", \"passkey_synced\", \"webauthn\"")},
            {"methods not sorted", ok.replace("\"passkey_device\", \"passkey_synced\"", "\"passkey_synced\", \"passkey_device\"")},
            {"method listed twice", ok.replace("\"passkey_device\", \"passkey_synced\"", "\"passkey_device\", \"passkey_device\", \"passkey_synced\"")},
            {"a family leaf", ok.replace("\"items\": [\"security_key\", \"yubikey_cert\"]", "\"items\": [\"family:yubikey\"]")},
            {"a leaf that is off", ok.replace("\"items\": [\"security_key\", \"yubikey_cert\"]", "\"items\": [\"password\"]")},
            {"a template id outside the rule", ok.replace("\"strong\": {", "\"Strong!\": {").replace("\"template\": \"strong\"", "\"template\": \"Strong!\"")},
            {"a client naming no template", ok.replace("\"template\": \"strong\"", "\"template\": \"__unpublished__\"")},
            {"a name as a number", ok.replace("\"name\": \"Nextcloud\"", "\"name\": 5")},
            {"a kind as a boolean", ok.replace("\"kind\": \"security_key\"", "\"kind\": true")},
            {"methods as a string", ok.replace("[\"passkey_device\", \"passkey_synced\", \"security_key\", \"yubikey_cert\"]", "\"security_key\"")},
            {"browser_cert on", ok.replace("\"passkey_device\", \"passkey_synced\"", "\"browser_cert\", \"passkey_device\", \"passkey_synced\"")},
            {"a null template", ok.replaceAll("\"strong\": \\{\"op\": \"any\", \"items\": \\[\"security_key\", \"yubikey_cert\"\\]\\}", "\"strong\": null")},
            {"a null client", ok.replace("\"nextcloud\": {\"template\": \"standard\", \"name\": \"Nextcloud\"}", "\"nextcloud\": null")},
            {"a client with an empty name", ok.replace("\"name\": \"Nextcloud\"", "\"name\": \"\"")},
            {"an empty client id", ok.replace("\"nextcloud\": {", "\"\": {")},
            {"an AAGUID in upper case", ok.replace(AAGUID, AAGUID.toUpperCase())},
            {"an AAGUID that isn't one", ok.replace(AAGUID, "not-an-aaguid")},
            {"an unknown kind", ok.replace("\"kind\": \"security_key\"", "\"kind\": \"passkey_synced\"")},
            {"an unknown status", ok.replace("\"status\": \"certified\"", "\"status\": \"FIDO_CERTIFIED\"")},
            {"no roots", ok.replaceAll("\"roots\": \\[\"[^\"]*\"\\]", "\"roots\": []")},
            {"a root that isn't base64", ok.replaceAll("\"roots\": \\[\"[^\"]*\"\\]", "\"roots\": [\"%%%\"]")},
            {"a root that isn't a certificate", ok.replaceAll("\"roots\": \\[\"[^\"]*\"\\]", "\"roots\": [\"AAAA\"]")},
            {"a null root", ok.replaceAll("\"roots\": \\[\"[^\"]*\"\\]", "\"roots\": [null]")},
            {"a negative serial", ok.replace("\"serial\": 87", "\"serial\": -1")},
            {"a serial as a string", ok.replace("\"serial\": 87", "\"serial\": \"87\"")},
            {"a next_update that isn't RFC 3339", ok.replace("2026-12-01T00:00:00Z", "December 1st")},
        };
        for (String[] b : bad) {
            assertNotEquals(ok, b[1], b[0] + ": the mutation applies");
            assertDenyAll(SigninConfig.load(write(dir, "bad.json", b[1])), b[0]);
        }
        assertDenyAll(SigninConfig.load(dir.resolve("absent.json")), "absent");
        assertDenyAll(SigninConfig.load(dir), "a directory");
        assertDenyAll(SigninConfig.load(null), "no path");
        // The default path doesn't exist on a test machine.
        if (!Files.exists(SigninConfig.PATH)) {
            assertDenyAll(SigninConfig.current(), "current() without the file");
        }
    }

    @Test
    void reloadsOnMtimeChange(@TempDir Path dir) throws Exception {
        Path p = dir.resolve("signin-keycloak.json");
        SigninConfig.Cache cache = new SigninConfig.Cache(p);
        assertDenyAll(cache.get(), "absent");

        Files.writeString(p, valid());
        FileTime t0 = FileTime.from(Instant.parse("2026-11-10T00:00:00Z"));
        Files.setLastModifiedTime(p, t0);
        SigninConfig first = cache.get();
        assertTrue(first.on("security_key"));
        assertSame(first, cache.get(), "unchanged file: the cached config");

        // Same size, same mtime: still cached (the file isn't read again).
        String same = valid().replace("\"serial\": 87", "\"serial\": 88");
        Files.writeString(p, same);
        Files.setLastModifiedTime(p, t0);
        assertSame(first, cache.get());

        // A new mtime: re-read.
        Files.setLastModifiedTime(p, FileTime.from(Instant.parse("2026-11-10T00:00:01Z")));
        SigninConfig second = cache.get();
        assertNotSame(first, second);
        assertEquals(88, second.mdsSerial());

        // Broken: DENY_ALL, then good again.
        Files.writeString(p, "{");
        Files.setLastModifiedTime(p, FileTime.from(Instant.parse("2026-11-10T00:00:02Z")));
        assertDenyAll(cache.get(), "broken");
        Files.writeString(p, valid());
        Files.setLastModifiedTime(p, FileTime.from(Instant.parse("2026-11-10T00:00:03Z")));
        assertEquals(87, cache.get().mdsSerial());

        // Removed: DENY_ALL.
        Files.delete(p);
        assertDenyAll(cache.get(), "removed");
    }
}
