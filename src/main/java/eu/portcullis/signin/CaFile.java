package eu.portcullis.signin;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The certificate authority file of a {@code portcullis-x509} execution
 * (its config's {@code portcullis.ca}; contract §8.1 "Flows"): the PEM (or
 * DER) certificate of the CA whose leaves that execution counts —
 * {@code pki_int} for YubiKey certificates, {@code pki_file} for browser
 * certificates. Read with the JDK's {@link CertificateFactory}, cached by
 * the file's mtime, size and file key (re-read when any changes).
 *
 * <p>Fail closed: a missing or unreadable file, anything but exactly one
 * certificate, or a certificate that isn't a CA (no basic constraints
 * {@code CA:true}) is empty, and the execution counts no leaf.
 */
final class CaFile {
    private CaFile() {}

    private record Stamp(long mtime, long size, Object fileKey) {}

    private record Cached(Stamp stamp, Optional<X509Certificate> ca) {}

    private static final ConcurrentHashMap<String, Cached> CACHE = new ConcurrentHashMap<>();

    /** The CA certificate at path, if the file holds exactly one CA certificate. */
    static Optional<X509Certificate> load(String path) {
        if (path == null || path.isBlank()) {
            return Optional.empty();
        }
        Path p;
        Stamp stamp;
        try {
            p = Path.of(path);
            BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class);
            if (!a.isRegularFile()) {
                CACHE.remove(path);
                return Optional.empty();
            }
            stamp = new Stamp(a.lastModifiedTime().toMillis(), a.size(), a.fileKey());
        } catch (IOException | RuntimeException e) {
            CACHE.remove(path);
            return Optional.empty();
        }
        Cached c = CACHE.get(path);
        if (c != null && Objects.equals(c.stamp(), stamp)) {
            return c.ca();
        }
        Optional<X509Certificate> ca = read(p);
        CACHE.put(path, new Cached(stamp, ca));
        return ca;
    }

    private static Optional<X509Certificate> read(Path p) {
        try (InputStream in = Files.newInputStream(p)) {
            Collection<? extends Certificate> all = CertificateFactory.getInstance("X.509").generateCertificates(in);
            if (all.size() != 1 || !(all.iterator().next() instanceof X509Certificate ca)) {
                return Optional.empty();
            }
            return ca.getBasicConstraints() >= 0 ? Optional.of(ca) : Optional.empty();
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            return Optional.empty();
        }
    }
}
