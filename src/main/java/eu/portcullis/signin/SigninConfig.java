package eu.portcullis.signin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.cfg.CoercionAction;
import com.fasterxml.jackson.databind.cfg.CoercionInputShape;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.type.LogicalType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.jboss.logging.Logger;

/**
 * The Hub's {@code signin-keycloak.json} (contract §8.1, plan D20): the
 * switched-on methods, the add-stronger switch, every enabled template's
 * compiled rule, the native-OIDC clients' templates, the passkey trust list
 * and the FIDO list it came from.
 *
 * <p>It is decoded strictly: unknown fields, trailing data, duplicate keys,
 * a missing field, {@code null}, a coerced scalar, another {@code version} or
 * any value outside its rule refuse the whole file. A missing, unreadable or
 * invalid file is {@link #DENY_ALL}: every method off and every client's
 * template unmeetable — nobody signs in until the Hub writes a good one.
 */
public final class SigninConfig {
    private static final Logger LOG = Logger.getLogger(SigninConfig.class);

    /** Where core mounts the Hub's data volume ({@code hub_data:/hub-data:ro}). */
    public static final Path PATH = Path.of("/hub-data/signin-keycloak.json");

    /** The only version this extension reads. */
    public static final int VERSION = 1;

    /** A file larger than this is refused (the FIDO list is a few MB at most). */
    static final long MAX_BYTES = 32L << 20;

    private static final Pattern TEMPLATE_ID = Pattern.compile("^[a-z][a-z0-9-]{0,31}$");
    private static final Set<String> KINDS = Set.of("security_key", "passkey_device");
    private static final Set<String> STATUSES = Set.of("certified", "revoked");

    /**
     * An authenticator model's entry in the trust list: kind
     * {@code security_key} or {@code passkey_device}, status
     * {@code certified} or {@code revoked}, the attestation roots.
     */
    public record Trust(String kind, String status, List<X509Certificate> roots) {
        public Trust {
            roots = List.copyOf(roots);
        }
    }

    /** Every method off, every client's template unmeetable, nothing trusted. */
    public static final SigninConfig DENY_ALL =
            new SigninConfig(true, Set.of(), false, Map.of(), Map.of(), Map.of(), -1, Instant.EPOCH);

    private final boolean denyAll;
    private final Set<String> methods;
    private final boolean addStronger;
    private final Map<String, Rule> templates;
    private final Map<String, Client> clients;
    private final Map<UUID, Trust> authenticators;
    private final long mdsSerial;
    private final Instant mdsNextUpdate;

    private record Client(String template, String name) {}

    private SigninConfig(boolean denyAll, Set<String> methods, boolean addStronger, Map<String, Rule> templates,
            Map<String, Client> clients, Map<UUID, Trust> authenticators, long mdsSerial, Instant mdsNextUpdate) {
        this.denyAll = denyAll;
        this.methods = methods;
        this.addStronger = addStronger;
        this.templates = templates;
        this.clients = clients;
        this.authenticators = authenticators;
        this.mdsSerial = mdsSerial;
        this.mdsNextUpdate = mdsNextUpdate;
    }

    /** Whether method is switched on (and not {@link Methods#UNAVAILABLE}). */
    public boolean on(String method) {
        return method != null && methods.contains(method) && !Methods.UNAVAILABLE.contains(method);
    }

    /** The switched-on methods, sorted. */
    public Set<String> methods() {
        return methods;
    }

    /** The Settings switch "add a stronger method" (off in {@link #DENY_ALL}). */
    public boolean addStronger() {
        return addStronger;
    }

    /** The FIDO list's serial ({@code mds.serial}); -1 in {@link #DENY_ALL}. */
    public long mdsSerial() {
        return mdsSerial;
    }

    /** The FIDO list's next update ({@code mds.next_update}). */
    public Instant mdsNextUpdate() {
        return mdsNextUpdate;
    }

    /**
     * The compiled template a client must meet. Empty for a client the file
     * doesn't list (left to group-gate). With {@link #DENY_ALL} every client
     * gets {@link Rule#UNMEETABLE}: an invalid file never lets a client
     * through as "unlisted".
     */
    public Optional<Rule> templateForClient(String clientId) {
        if (denyAll) {
            return Optional.of(Rule.UNMEETABLE);
        }
        Client c = clientId == null ? null : clients.get(clientId);
        if (c == null) {
            return Optional.empty();
        }
        return Optional.of(templates.getOrDefault(c.template(), Rule.UNMEETABLE));
    }

    /** The instance name the needs-stronger page shows for a listed client. */
    public Optional<String> clientName(String clientId) {
        Client c = clientId == null ? null : clients.get(clientId);
        return c == null ? Optional.empty() : Optional.of(c.name());
    }

    /** The trust-list entry of an authenticator model. */
    public Optional<Trust> authenticator(UUID aaguid) {
        return aaguid == null ? Optional.empty() : Optional.ofNullable(authenticators.get(aaguid));
    }

    // ── Loading ──

    private record FileJson(
            @JsonProperty(value = "version", required = true) int version,
            @JsonProperty(value = "methods", required = true) List<String> methods,
            @JsonProperty(value = "add_stronger", required = true) boolean addStronger,
            @JsonProperty(value = "templates", required = true) Map<String, JsonNode> templates,
            @JsonProperty(value = "clients", required = true) Map<String, ClientJson> clients,
            @JsonProperty(value = "authenticators", required = true) Map<String, TrustJson> authenticators,
            @JsonProperty(value = "mds", required = true) MdsJson mds) {}

    private record ClientJson(
            @JsonProperty(value = "template", required = true) String template,
            @JsonProperty(value = "name", required = true) String name) {}

    private record TrustJson(
            @JsonProperty(value = "kind", required = true) String kind,
            @JsonProperty(value = "status", required = true) String status,
            @JsonProperty(value = "roots", required = true) List<String> roots) {}

    private record MdsJson(
            @JsonProperty(value = "serial", required = true) long serial,
            @JsonProperty(value = "next_update", required = true) String nextUpdate) {}

    private static final ObjectMapper MAPPER = strictMapper();

    /** The strict decoding every Hub file gets (also {@link ImpersonationFile}). */
    static ObjectMapper strictMapper() {
        JsonMapper m = JsonMapper.builder()
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
                .enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
                .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT)
                .disable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
                .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
                .build();
        // No scalar becomes another kind of scalar: "1" is no int, 1 no string, 0 no boolean.
        for (LogicalType t : new LogicalType[] {LogicalType.Textual, LogicalType.Integer, LogicalType.Boolean, LogicalType.Float}) {
            m.coercionConfigFor(t)
                    .setCoercion(CoercionInputShape.String, t == LogicalType.Textual ? CoercionAction.TryConvert : CoercionAction.Fail)
                    .setCoercion(CoercionInputShape.Integer, t == LogicalType.Integer ? CoercionAction.TryConvert : CoercionAction.Fail)
                    .setCoercion(CoercionInputShape.Float, CoercionAction.Fail)
                    .setCoercion(CoercionInputShape.Boolean, t == LogicalType.Boolean ? CoercionAction.TryConvert : CoercionAction.Fail)
                    .setCoercion(CoercionInputShape.EmptyString, CoercionAction.Fail);
        }
        return m;
    }

    /**
     * Reads and validates the file at p. Never throws: anything wrong is
     * {@link #DENY_ALL}, logged with the reason (never the file's content).
     */
    public static SigninConfig load(Path p) {
        if (p == null) {
            return DENY_ALL;
        }
        try {
            return parse(read(p));
        } catch (NoSuchFileException e) {
            LOG.warnf("portcullis: %s is missing: every sign-in method is off until the Hub writes it", p);
        } catch (IOException | RuntimeException e) {
            LOG.errorf("portcullis: %s refused (%s): every sign-in method is off until the Hub writes a valid one",
                    p, clip(e));
        }
        return DENY_ALL;
    }

    private static byte[] read(Path p) throws IOException {
        try (InputStream in = Files.newInputStream(p)) {
            byte[] b = in.readNBytes((int) MAX_BYTES + 1);
            if (b.length > MAX_BYTES) {
                throw new IOException("larger than " + MAX_BYTES + " bytes");
            }
            return b;
        }
    }

    private static String clip(Throwable e) {
        String m = e.getClass().getSimpleName() + ": " + Objects.toString(e.getMessage(), "");
        m = m.replaceAll("\\p{Cntrl}", " ");
        return m.length() > 300 ? m.substring(0, 300) + "…" : m;
    }

    static SigninConfig parse(byte[] raw) throws IOException {
        FileJson f = MAPPER.readValue(raw, FileJson.class);
        if (f.version() != VERSION) {
            throw new IllegalArgumentException("version " + f.version() + ", want " + VERSION);
        }

        // methods: switched-on ids, sorted, each once; none of Methods.UNAVAILABLE.
        List<String> ms = f.methods();
        Set<String> methods = new LinkedHashSet<>();
        String prev = null;
        for (String m : ms) {
            if (!Methods.known(m) || Methods.UNAVAILABLE.contains(m)) {
                throw new IllegalArgumentException("methods: not a method that can be on");
            }
            if (prev != null && prev.compareTo(m) >= 0) {
                throw new IllegalArgumentException("methods: not sorted, or listed twice");
            }
            methods.add(m);
            prev = m;
        }

        // templates: id → compiled rule, every leaf switched on.
        Map<String, Rule> templates = new HashMap<>();
        for (Map.Entry<String, JsonNode> e : f.templates().entrySet()) {
            if (!TEMPLATE_ID.matcher(e.getKey()).matches()) {
                throw new IllegalArgumentException("templates: an id outside ^[a-z][a-z0-9-]{0,31}$");
            }
            Rule r = Rule.parse(e.getValue());
            if (!r.leavesIn(methods)) {
                throw new IllegalArgumentException("templates." + e.getKey() + ": names a method that is off");
            }
            templates.put(e.getKey(), r);
        }

        // clients: client id → {template (a key of templates), name}.
        Map<String, Client> clients = new HashMap<>();
        for (Map.Entry<String, ClientJson> e : f.clients().entrySet()) {
            ClientJson c = e.getValue();
            if (e.getKey().isEmpty() || hasControl(e.getKey())) {
                throw new IllegalArgumentException("clients: an empty or unprintable client id");
            }
            if (c == null || !templates.containsKey(c.template())) {
                throw new IllegalArgumentException("clients: a client whose template isn't published");
            }
            if (c.name().isEmpty()) {
                throw new IllegalArgumentException("clients: an empty name");
            }
            clients.put(e.getKey(), new Client(c.template(), c.name()));
        }

        // authenticators: AAGUID (lowercase, hyphenated) → {kind, status, roots}.
        Map<UUID, Trust> authenticators = new HashMap<>();
        CertificateFactory x509;
        try {
            x509 = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
        for (Map.Entry<String, TrustJson> e : f.authenticators().entrySet()) {
            UUID aaguid;
            try {
                aaguid = UUID.fromString(e.getKey());
            } catch (IllegalArgumentException x) {
                throw new IllegalArgumentException("authenticators: a key that isn't an AAGUID");
            }
            if (!aaguid.toString().equals(e.getKey())) {
                throw new IllegalArgumentException("authenticators: an AAGUID not lowercase and hyphenated");
            }
            TrustJson t = e.getValue();
            if (t == null || !KINDS.contains(t.kind()) || !STATUSES.contains(t.status())) {
                throw new IllegalArgumentException("authenticators: an unknown kind or status");
            }
            // Contract §8.1: the Hub always publishes a revoked entry, with
            // `roots: []` when none of its roots is usable (a revocation
            // needs none); every other entry needs at least one root.
            if (t.roots().isEmpty() && !"revoked".equals(t.status())) {
                throw new IllegalArgumentException("authenticators: a certified entry without roots");
            }
            List<X509Certificate> roots = new ArrayList<>(t.roots().size());
            boolean readable = true;
            for (String b64 : t.roots()) {
                Optional<X509Certificate> c = certificate(x509, b64);
                if (c.isEmpty()) {
                    readable = false;
                    break;
                }
                roots.add(c.get());
            }
            if (!readable) {
                // Contract §8.1 "Unreadable roots": one entry the JDK can't
                // read never denies every sign-in. A revoked entry is kept
                // without roots (revocation needs none: it still downgrades);
                // any other is left out, so that model's passkeys count as
                // synced until the list is fixed.
                if ("revoked".equals(t.status())) {
                    LOG.warnf("portcullis: trust-list entry %s (revoked) kept without its roots: a root isn't exactly one DER X.509 certificate", aaguid);
                    authenticators.put(aaguid, new Trust(t.kind(), t.status(), List.of()));
                } else {
                    LOG.warnf("portcullis: trust-list entry %s left out: a root isn't exactly one DER X.509 certificate", aaguid);
                }
                continue;
            }
            authenticators.put(aaguid, new Trust(t.kind(), t.status(), roots));
        }

        // mds: {serial ≥ 0, next_update RFC 3339}.
        if (f.mds().serial() < 0) {
            throw new IllegalArgumentException("mds.serial below 0");
        }
        Instant next;
        try {
            next = OffsetDateTime.parse(f.mds().nextUpdate(), DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant();
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("mds.next_update isn't RFC 3339");
        }

        return new SigninConfig(false, Collections.unmodifiableSet(methods), f.addStronger(),
                Map.copyOf(templates), Map.copyOf(clients), Map.copyOf(authenticators), f.mds().serial(), next);
    }

    /**
     * A root: standard base64 (else the whole file is refused) of exactly one
     * DER certificate (else empty: the caller leaves that entry out).
     */
    private static Optional<X509Certificate> certificate(CertificateFactory x509, String b64) {
        if (b64 == null) {
            throw new IllegalArgumentException("authenticators: a null root");
        }
        byte[] der;
        try {
            der = Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("authenticators: a root that isn't standard base64");
        }
        try {
            Certificate c = x509.generateCertificate(new ByteArrayInputStream(der));
            if (c instanceof X509Certificate x && Arrays.equals(x.getEncoded(), der)) {
                return Optional.of(x);
            }
        } catch (CertificateException | RuntimeException e) {
            // not a certificate the JDK reads: the entry is left out
        }
        return Optional.empty();
    }

    private static boolean hasControl(String s) {
        return s.codePoints().anyMatch(Character::isISOControl);
    }

    // ── The cached current file ──

    /** The file at a path, re-read whenever its mtime, size or file key changes. */
    static final class Cache {
        private record Stamp(FileTime mtime, long size, Object fileKey) {}

        private final Path path;
        private Stamp stamp;
        private SigninConfig config = DENY_ALL;
        private boolean loaded;

        Cache(Path path) {
            this.path = path;
        }

        synchronized SigninConfig get() {
            Stamp now;
            try {
                BasicFileAttributes a = Files.readAttributes(path, BasicFileAttributes.class);
                now = new Stamp(a.lastModifiedTime(), a.size(), a.fileKey());
            } catch (IOException | RuntimeException e) {
                now = null;
            }
            if (loaded && Objects.equals(now, stamp)) {
                return config;
            }
            config = load(path); // logs why when it is DENY_ALL
            stamp = now;
            loaded = true;
            return config;
        }
    }

    private static final Cache CURRENT = new Cache(PATH);

    /** {@code /hub-data/signin-keycloak.json}, cached by mtime (DENY_ALL when missing or invalid). */
    public static SigninConfig current() {
        return CURRENT.get();
    }
}
