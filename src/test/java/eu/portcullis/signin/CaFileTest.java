package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** portcullis.ca files: exactly one CA certificate, read with the JDK, cached by mtime; anything else empty. */
class CaFileTest {
    @TempDir
    Path dir;

    @Test
    void readsOneCaCertificate() throws Exception {
        Path p = TestCas.YUBIKEY.pem(dir, "yubikey.pem");
        assertEquals(TestCas.YUBIKEY.cert(), CaFile.load(p.toString()).orElseThrow());
        Path der = dir.resolve("browser.der");
        Files.write(der, TestCas.BROWSER.cert().getEncoded());
        assertEquals(TestCas.BROWSER.cert(), CaFile.load(der.toString()).orElseThrow());
    }

    @Test
    void anythingElseIsEmpty() throws Exception {
        assertFalse(CaFile.load(null).isPresent());
        assertFalse(CaFile.load("").isPresent());
        assertFalse(CaFile.load(dir.resolve("missing.pem").toString()).isPresent());
        assertFalse(CaFile.load(dir.toString()).isPresent(), "a directory");
        Path junk = Files.writeString(dir.resolve("junk.pem"), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
        assertFalse(CaFile.load(junk.toString()).isPresent());
        Path empty = Files.writeString(dir.resolve("empty.pem"), "");
        assertFalse(CaFile.load(empty.toString()).isPresent());
        Path leaf = Files.writeString(dir.resolve("leaf.pem"), TestCas.pem(TestCas.YUBIKEY.leaf("alice")));
        assertFalse(CaFile.load(leaf.toString()).isPresent(), "not a CA");
        Path two = Files.writeString(dir.resolve("two.pem"), TestCas.pem(TestCas.YUBIKEY.cert()) + TestCas.pem(TestCas.BROWSER.cert()));
        assertFalse(CaFile.load(two.toString()).isPresent(), "a chain, not one CA");
    }

    @Test
    void reReadWhenTheFileChanges() throws Exception {
        Path p = TestCas.YUBIKEY.pem(dir, "ca.pem");
        assertEquals(TestCas.YUBIKEY.cert(), CaFile.load(p.toString()).orElseThrow());
        Files.writeString(p, TestCas.pem(TestCas.BROWSER.cert()));
        Files.setLastModifiedTime(p, FileTime.from(Instant.now().plusSeconds(5)));
        assertEquals(TestCas.BROWSER.cert(), CaFile.load(p.toString()).orElseThrow());
        Files.delete(p);
        assertFalse(CaFile.load(p.toString()).isPresent(), "gone: no cached answer");
        TestCas.YUBIKEY.pem(dir, "ca.pem");
        assertTrue(CaFile.load(p.toString()).isPresent());
    }
}
