package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.models.AuthenticatorConfigModel;

/**
 * The {@code mtls} amr invariant (contract §8): each {@code portcullis-x509}
 * execution counts only a leaf its own CA issued — a browser
 * ({@code pki_file}) certificate never signs in as {@code yubikey_cert}
 * (amr {@code mtls}), a YubiKey ({@code pki_int}) one never as
 * {@code browser_cert} (amr {@code file}). Keycloak's own X.509 code runs.
 */
class X509AuthenticatorTest {
    static {
        X509StepTest.crypto();
    }

    static final String ALL = "\"browser_cert\", \"passkey_device\", \"passkey_synced\", \"security_key\", \"yubikey_cert\"";
    static final SigninConfig BOTH = Configs.of(ALL, false, "", "");

    @TempDir
    Path dir;

    /** The execution's config: X.509 settings, its method, reference value and CA file. */
    static Map<String, String> config(String method, Path ca) {
        Map<String, String> c = new HashMap<>(X509StepTest.X509);
        c.put(X509Authenticator.METHOD_CONFIG, method);
        c.put("default.reference.value", "browser_cert".equals(method) ? "file" : "mtls");
        c.put(X509Authenticator.CA_CONFIG, ca.toString());
        return c;
    }

    /** alice exists; the request presents leaf (null: none) to an execution of method with CA file ca. */
    static Flow presenting(String method, Path ca, X509Certificate leaf) {
        Flow f = new Flow();
        f.person("u-alice", "alice");
        f.headers.put("User-Agent", "Firefox/140 (Mac)");
        f.certificates = leaf == null ? null : new X509Certificate[] {leaf};
        f.config(config(method, ca));
        return f;
    }

    Path yubikeyCa() throws Exception {
        return TestCas.YUBIKEY.pem(dir, "portcullis-yubikey-ca.pem");
    }

    Path browserCa() throws Exception {
        return TestCas.BROWSER.pem(dir, "portcullis-browser-ca.pem");
    }

    @Test
    void browserLeafNeverMtls() throws Exception {
        Flow f = presenting("yubikey_cert", yubikeyCa(), TestCas.BROWSER.leaf("alice"));
        new X509Authenticator(false, () -> BOTH).authenticate(f.context);
        assertEquals(FlowStatus.ATTEMPTED, f.status);
        assertNull(f.user);
        assertNull(f.authNotes.get(X509Authenticator.METHOD_NOTE), "no yubikey_cert, so no mtls amr");
        // Even named as the YubiKey CA's but signed by the browser CA's key.
        Flow forged = presenting("yubikey_cert", yubikeyCa(), TestCas.issue(TestCas.YUBIKEY.cert(), TestCas.BROWSER.key(), "alice"));
        new X509Authenticator(false, () -> BOTH).authenticate(forged.context);
        assertEquals(FlowStatus.ATTEMPTED, forged.status);
        assertNull(forged.authNotes.get(X509Authenticator.METHOD_NOTE));
    }

    @Test
    void yubikeyLeafNeverFile() throws Exception {
        Flow f = presenting("browser_cert", browserCa(), TestCas.YUBIKEY.leaf("alice"));
        new X509Authenticator(false, () -> BOTH).authenticate(f.context);
        assertEquals(FlowStatus.ATTEMPTED, f.status);
        assertNull(f.user);
        assertNull(f.authNotes.get(X509Authenticator.METHOD_NOTE));
    }

    @Test
    void yubikeyLeafSignsInAsMtls() throws Exception {
        Flow f = presenting("yubikey_cert", yubikeyCa(), TestCas.YUBIKEY.leaf("alice"));
        new X509Authenticator(false, () -> BOTH).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
        assertEquals("u-alice", f.user.getId());
        assertEquals("yubikey_cert", f.authNotes.get(X509Authenticator.METHOD_NOTE));
    }

    @Test
    void browserLeafSignsInAsFile() throws Exception {
        Flow f = presenting("browser_cert", browserCa(), TestCas.BROWSER.leaf("alice"));
        new X509Authenticator(false, () -> BOTH).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
        assertEquals("u-alice", f.user.getId());
        assertEquals("browser_cert", f.authNotes.get(X509Authenticator.METHOD_NOTE));

        Flow off = presenting("browser_cert", browserCa(), TestCas.BROWSER.leaf("alice"));
        new X509Authenticator(false, Configs::plain).authenticate(off.context); // browser_cert off
        assertEquals(FlowStatus.ATTEMPTED, off.status);
        assertNull(off.user);

        Flow other = presenting("browser_cert", browserCa(), TestCas.BROWSER.leaf("alice"));
        other.clientNotes.put(PcMethod.CLIENT_NOTE, "yubikey_cert");
        new X509Authenticator(false, () -> BOTH).authenticate(other.context);
        assertEquals(FlowStatus.ATTEMPTED, other.status, "pc_method asks for the YubiKey certificate");
    }

    /** Records the ERROR (SEVERE and up) messages of X509Authenticator's logger. */
    private static List<String> errors(Runnable r) {
        java.util.logging.Logger jul = java.util.logging.Logger.getLogger(X509Authenticator.class.getName());
        List<String> out = new ArrayList<>();
        Handler h = new Handler() {
            @Override
            public void publish(LogRecord rec) {
                if (rec.getLevel().intValue() >= Level.SEVERE.intValue()) {
                    out.add(String.valueOf(rec.getMessage()));
                }
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };
        jul.addHandler(h);
        try {
            r.run();
        } finally {
            jul.removeHandler(h);
        }
        return out;
    }

    @Test
    void caFileMissingStepsAside() throws Exception {
        for (Path ca : new Path[] {dir.resolve("missing.pem"), java.nio.file.Files.writeString(dir.resolve("junk.pem"), "not a certificate")}) {
            Flow f = presenting("yubikey_cert", ca, TestCas.YUBIKEY.leaf("alice"));
            List<String> logged = errors(() -> new X509Authenticator(false, () -> BOTH).authenticate(f.context));
            assertEquals(FlowStatus.ATTEMPTED, f.status, ca.toString());
            assertNull(f.user);
            assertNull(f.authNotes.get(X509Authenticator.METHOD_NOTE));
            assertEquals(1, logged.size(), "one ERROR: " + logged);
            assertTrue(logged.get(0).contains("portcullis"), logged.get(0));
        }
        // A certificate that isn't a CA: no leaf counts either.
        Path leafFile = dir.resolve("leaf.pem");
        java.nio.file.Files.writeString(leafFile, TestCas.pem(TestCas.YUBIKEY.leaf("ca")));
        Flow f = presenting("yubikey_cert", leafFile, TestCas.YUBIKEY.leaf("alice"));
        new X509Authenticator(false, () -> BOTH).authenticate(f.context);
        assertEquals(FlowStatus.ATTEMPTED, f.status);
    }

    @Test
    void noLeafNeverReadsCaFile() throws Exception {
        AtomicInteger reads = new AtomicInteger();
        Function<String, Optional<X509Certificate>> counting = p -> {
            reads.incrementAndGet();
            return CaFile.load(p);
        };
        Flow f = presenting("yubikey_cert", dir.resolve("missing.pem"), null);
        List<String> logged = errors(() -> new X509Authenticator(false, () -> BOTH, counting).authenticate(f.context));
        assertEquals(FlowStatus.ATTEMPTED, f.status);
        assertEquals(0, reads.get(), "no certificate: the CA file is never read");
        assertEquals(List.of(), logged);
        assertFalse(new X509Authenticator(false, () -> BOTH, counting).certificateUser(f.context, f.authenticatorConfig).isPresent());
        assertEquals(0, reads.get());

        // The method off: never read either, even with a leaf.
        Flow off = presenting("browser_cert", dir.resolve("missing.pem"), TestCas.BROWSER.leaf("alice"));
        new X509Authenticator(false, Configs::plain, counting).authenticate(off.context);
        assertEquals(FlowStatus.ATTEMPTED, off.status);
        assertEquals(0, reads.get());
    }

    @Test
    void unknownMethodConfigStepsAside() throws Exception {
        for (String m : new String[] {"mtls", "file", "password", "security_key", "YUBIKEY_CERT", ""}) {
            Flow f = presenting(m, yubikeyCa(), TestCas.YUBIKEY.leaf("alice"));
            new X509Authenticator(false, () -> BOTH).authenticate(f.context);
            assertEquals(FlowStatus.ATTEMPTED, f.status, m);
            assertNull(f.user, m);
        }
        Flow none = presenting("yubikey_cert", yubikeyCa(), TestCas.YUBIKEY.leaf("alice"));
        none.authenticatorConfig.getConfig().remove(X509Authenticator.METHOD_CONFIG);
        new X509Authenticator(false, () -> BOTH).authenticate(none.context);
        assertEquals(FlowStatus.ATTEMPTED, none.status, "no portcullis.method");
        assertNull(X509Authenticator.method(null));
        assertNull(X509Authenticator.method(new AuthenticatorConfigModel()));
    }

    @Test
    void issuedByChecksSignatureNotJustName() {
        X509Certificate forged = TestCas.issue(TestCas.YUBIKEY.cert(), TestCas.BROWSER.key(), "alice");
        assertEquals(TestCas.YUBIKEY.cert().getSubjectX500Principal(), forged.getIssuerX500Principal());
        assertFalse(X509Authenticator.issuedBy(forged, TestCas.YUBIKEY.cert()), "the issuer name alone isn't enough");
        assertFalse(X509Authenticator.issuedBy(forged, TestCas.BROWSER.cert()), "the key alone isn't enough");
        assertTrue(X509Authenticator.issuedBy(TestCas.YUBIKEY.leaf("alice"), TestCas.YUBIKEY.cert()));
        assertTrue(X509Authenticator.issuedBy(TestCas.BROWSER.leaf("alice"), TestCas.BROWSER.cert()));
        assertFalse(X509Authenticator.issuedBy(TestCas.BROWSER.leaf("alice"), TestCas.YUBIKEY.cert()));
        assertFalse(X509Authenticator.issuedBy(null, TestCas.YUBIKEY.cert()));
        assertFalse(X509Authenticator.issuedBy(TestCas.YUBIKEY.leaf("alice"), null));
        assertNotEquals(TestCas.YUBIKEY.cert().getSubjectX500Principal(), TestCas.BROWSER.cert().getSubjectX500Principal());
    }

    @Test
    void failureHasMethodAndUa() throws Exception {
        // A browser certificate of an account Keycloak doesn't know: refused by the stock code.
        Flow f = presenting("browser_cert", browserCa(), TestCas.BROWSER.leaf("nobody"));
        new X509Authenticator(false, () -> BOTH).authenticate(f.context);
        assertFalse(f.status == FlowStatus.SUCCESS);
        assertEquals(List.of("user_not_found"), f.eventErrors);
        assertEquals("browser_cert", f.errorDetails.get(0).get(History.METHOD));
        assertEquals("Firefox/140 (Mac)", f.errorDetails.get(0).get(History.UA));
    }

    @Test
    void skippedWhenOffOrOtherMethodRequested() throws Exception {
        Flow off = presenting("yubikey_cert", yubikeyCa(), TestCas.YUBIKEY.leaf("alice"));
        new X509Authenticator(false, () -> Configs.of("\"security_key\"", false, "", "")).authenticate(off.context);
        assertEquals(FlowStatus.ATTEMPTED, off.status);

        Flow other = presenting("yubikey_cert", yubikeyCa(), TestCas.YUBIKEY.leaf("alice"));
        other.clientNotes.put(PcMethod.CLIENT_NOTE, "passkey");
        new X509Authenticator(false, Configs::plain).authenticate(other.context);
        assertEquals(FlowStatus.ATTEMPTED, other.status);

        Flow deny = presenting("yubikey_cert", yubikeyCa(), TestCas.YUBIKEY.leaf("alice"));
        new X509Authenticator(false, () -> SigninConfig.DENY_ALL).action(deny.context);
        assertEquals(AuthenticationFlowError.ACCESS_DENIED, deny.error);
    }

    @Test
    void confirmationNeedsItsOwnLeaf() throws Exception {
        Flow f = presenting("yubikey_cert", yubikeyCa(), TestCas.YUBIKEY.leaf("alice"));
        f.user = f.users.get("alice"); // the stock confirmation page set her
        new X509Authenticator(false, Configs::plain).action(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
        assertEquals("yubikey_cert", f.authNotes.get(X509Authenticator.METHOD_NOTE));

        Flow browser = presenting("yubikey_cert", yubikeyCa(), TestCas.BROWSER.leaf("alice"));
        browser.user = browser.users.get("alice");
        new X509Authenticator(false, () -> BOTH).action(browser.context);
        assertEquals(AuthenticationFlowError.ACCESS_DENIED, browser.error, "a browser leaf never confirms a YubiKey sign-in");
        assertNull(browser.authNotes.get(X509Authenticator.METHOD_NOTE));

        Flow none = presenting("yubikey_cert", yubikeyCa(), null);
        none.user = none.users.get("alice");
        new X509Authenticator(false, Configs::plain).action(none.context);
        assertEquals(AuthenticationFlowError.ACCESS_DENIED, none.error);
    }

    /** The request presents this chain to an execution of method; it must step aside (no note, nobody signed in). */
    private static void stepsAside(String method, Path ca, String why, X509Certificate... chain) {
        Flow f = presenting(method, ca, chain[0]);
        f.certificates = chain;
        new X509Authenticator(false, () -> BOTH).authenticate(f.context);
        assertEquals(FlowStatus.ATTEMPTED, f.status, why);
        assertNull(f.user, why);
        assertNull(f.authNotes.get(X509Authenticator.METHOD_NOTE), why + ": never mtls or file");
    }

    @Test
    void selfSignedLeafStepsAside() throws Exception {
        X509Certificate self = TestCas.selfSigned("CN=alice, O=Portcullis Test");
        assertEquals(self.getSubjectX500Principal(), self.getIssuerX500Principal());
        stepsAside("yubikey_cert", yubikeyCa(), "self-signed", self);
        stepsAside("browser_cert", browserCa(), "self-signed", self);
        // Self-signed under the CA's own name (a look-alike CA): the name matches, the signature doesn't.
        X509Certificate likeYubikey = TestCas.selfSigned(TestCas.YUBIKEY.cert().getSubjectX500Principal().getName());
        assertEquals(TestCas.YUBIKEY.cert().getSubjectX500Principal(), likeYubikey.getIssuerX500Principal());
        stepsAside("yubikey_cert", yubikeyCa(), "a self-signed look-alike of the YubiKey CA", likeYubikey);
        X509Certificate likeBrowser = TestCas.selfSigned(TestCas.BROWSER.cert().getSubjectX500Principal().getName());
        stepsAside("browser_cert", browserCa(), "a self-signed look-alike of the browser CA", likeBrowser);
    }

    @Test
    void intermediateAsLeafStepsAside() throws Exception {
        for (String m : new String[] {"yubikey_cert", "browser_cert"}) {
            Path ca = "yubikey_cert".equals(m) ? yubikeyCa() : browserCa();
            stepsAside(m, ca, m + ": the YubiKey CA presented as the leaf", TestCas.YUBIKEY.cert());
            stepsAside(m, ca, m + ": the browser CA presented as the leaf", TestCas.BROWSER.cert());
            stepsAside(m, ca, m + ": the root presented as the leaf", com.webauthn4j.test.TestAttestationUtil.load3tierTestRootCACertificate());
        }
    }

    @Test
    void onlyChainZeroIsJudged() throws Exception {
        // The other kind's leaf first, this execution's own leaf second: chain[0] decides, so it steps aside.
        stepsAside("yubikey_cert", yubikeyCa(), "browser leaf first", TestCas.BROWSER.leaf("alice"), TestCas.YUBIKEY.leaf("alice"));
        stepsAside("browser_cert", browserCa(), "YubiKey leaf first", TestCas.YUBIKEY.leaf("alice"), TestCas.BROWSER.leaf("alice"));
        // The CA itself after a leaf of the other kind: still chain[0] only.
        stepsAside("yubikey_cert", yubikeyCa(), "browser leaf + the YubiKey CA", TestCas.BROWSER.leaf("alice"), TestCas.YUBIKEY.cert());
        // And the other way: its own leaf first, an extra certificate after, signs in as its own method only.
        Flow f = presenting("yubikey_cert", yubikeyCa(), TestCas.YUBIKEY.leaf("alice"));
        f.certificates = new X509Certificate[] {TestCas.YUBIKEY.leaf("alice"), TestCas.BROWSER.leaf("alice")};
        new X509Authenticator(false, () -> BOTH).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
        assertEquals("yubikey_cert", f.authNotes.get(X509Authenticator.METHOD_NOTE));
        Flow b = presenting("browser_cert", browserCa(), TestCas.BROWSER.leaf("alice"));
        b.certificates = new X509Certificate[] {TestCas.BROWSER.leaf("alice"), TestCas.YUBIKEY.leaf("alice")};
        new X509Authenticator(false, () -> BOTH).authenticate(b.context);
        assertEquals("browser_cert", b.authNotes.get(X509Authenticator.METHOD_NOTE));
    }
}
