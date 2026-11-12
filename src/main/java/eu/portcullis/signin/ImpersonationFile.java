package eu.portcullis.signin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.jboss.logging.Logger;

/**
 * The Hub's {@code hub_data/impersonation.json} (contract §8.1
 * "Impersonation", plan D37): the Settings switch, the clients an
 * impersonated session may sign in to, the pending starts, the running and
 * recently ended impersonations, and the people's unseen notices.
 *
 * <p>Decoded strictly, as {@link SigninConfig} is: unknown fields, trailing
 * data, duplicate keys, a missing field, a {@code null} where none is
 * allowed (only {@code sessions[].ended} may be {@code null}), a coerced
 * scalar, another {@code version}, an id twice, or any value outside its
 * rule (usernames {@code ^[a-z0-9][a-z0-9._-]{0,63}$}, ids
 * {@code ^[0-9a-f]{32}$}, reasons 3–200 runes with no control or bidi
 * character, RFC 3339 times, {@code fresh} a touch method) refuse the whole
 * file. A missing, unreadable or invalid file is {@link #DENY}: not allowed,
 * nothing pending, nothing live.
 */
final class ImpersonationFile {
    private static final Logger LOG = Logger.getLogger(ImpersonationFile.class);

    /** Where core mounts the Hub's data volume ({@code hub_data:/hub-data:ro}). */
    static final Path PATH = Path.of("/hub-data/impersonation.json");

    static final int VERSION = 1;

    /** A larger file is refused (a few KB in practice). */
    static final long MAX_BYTES = 4L << 20;

    static final Pattern USERNAME = Pattern.compile("^[a-z0-9][a-z0-9._-]{0,63}$");
    static final Pattern ID = Pattern.compile("^[0-9a-f]{32}$");
    /** A Keycloak user session id (a UUID today); never a path or a space. */
    private static final Pattern SESSION_ID = Pattern.compile("^[A-Za-z0-9._:~-]{1,128}$");
    /** The fresh touch D36 accepts: a security key or a YubiKey certificate. */
    static final Set<String> TOUCH_METHODS = Set.of("security_key", "yubikey_cert");

    record Pending(String id, String admin, String adminSid, String target, String reason, String fresh, Instant freshAt,
            Instant created, Instant until) {}

    record SessionRec(String id, String admin, String target, String reason, Instant started, Instant until, Instant ended) {}

    record Notice(String id, String admin, Instant started, Instant ended, String reason, List<App> apps) {}

    record App(String name, boolean ownSession) {}

    /** Not allowed, nothing pending, nothing running, no notices. */
    static final ImpersonationFile DENY = new ImpersonationFile(false, Set.of(), Map.of(), Map.of(), Map.of());

    private final boolean allowed;
    private final Set<String> clients;
    private final Map<String, Pending> pending;
    private final Map<String, SessionRec> sessions;
    private final Map<String, List<Notice>> notices;

    private ImpersonationFile(boolean allowed, Set<String> clients, Map<String, Pending> pending, Map<String, SessionRec> sessions,
            Map<String, List<Notice>> notices) {
        this.allowed = allowed;
        this.clients = clients;
        this.pending = pending;
        this.sessions = sessions;
        this.notices = notices;
    }

    /** The Settings switch "Signing in as someone else" (false in {@link #DENY}). */
    boolean allowed() {
        return allowed;
    }

    /** The clients an impersonated session may sign in to. */
    Set<String> clients() {
        return clients;
    }

    Optional<Pending> pending(String id) {
        return id == null ? Optional.empty() : Optional.ofNullable(pending.get(id));
    }

    Optional<SessionRec> session(String id) {
        return id == null ? Optional.empty() : Optional.ofNullable(sessions.get(id));
    }

    /** The person's notices (empty when none). */
    List<Notice> notices(String user) {
        return user == null ? List.of() : notices.getOrDefault(user, List.of());
    }

    /** Every person the pending and session records name (the expiry walks their sessions). */
    Set<String> targets() {
        Set<String> out = new LinkedHashSet<>();
        pending.values().forEach(p -> out.add(p.target()));
        sessions.values().forEach(s -> out.add(s.target()));
        return Collections.unmodifiableSet(out);
    }

    // ── Loading ──

    private record FileJson(
            @JsonProperty(value = "version", required = true) int version,
            @JsonProperty(value = "allowed", required = true) boolean allowed,
            @JsonProperty(value = "written", required = true) String written,
            @JsonProperty(value = "clients", required = true) List<String> clients,
            @JsonProperty(value = "pending", required = true) List<PendingJson> pending,
            @JsonProperty(value = "sessions", required = true) List<SessionJson> sessions,
            @JsonProperty(value = "notices", required = true) Map<String, List<NoticeJson>> notices) {}

    private record PendingJson(
            @JsonProperty(value = "id", required = true) String id,
            @JsonProperty(value = "admin", required = true) String admin,
            @JsonProperty(value = "admin_sid", required = true) String adminSid,
            @JsonProperty(value = "target", required = true) String target,
            @JsonProperty(value = "reason", required = true) String reason,
            @JsonProperty(value = "fresh", required = true) String fresh,
            @JsonProperty(value = "fresh_at", required = true) String freshAt,
            @JsonProperty(value = "created", required = true) String created,
            @JsonProperty(value = "until", required = true) String until) {}

    /** {@code ended} is a node: {@code null} (running) or an RFC 3339 string, nothing else. */
    private record SessionJson(
            @JsonProperty(value = "id", required = true) String id,
            @JsonProperty(value = "admin", required = true) String admin,
            @JsonProperty(value = "target", required = true) String target,
            @JsonProperty(value = "reason", required = true) String reason,
            @JsonProperty(value = "started", required = true) String started,
            @JsonProperty(value = "until", required = true) String until,
            @JsonProperty(value = "ended", required = true) JsonNode ended) {}

    private record NoticeJson(
            @JsonProperty(value = "id", required = true) String id,
            @JsonProperty(value = "admin", required = true) String admin,
            @JsonProperty(value = "started", required = true) String started,
            @JsonProperty(value = "ended", required = true) String ended,
            @JsonProperty(value = "reason", required = true) String reason,
            @JsonProperty(value = "apps", required = true) List<AppJson> apps) {}

    private record AppJson(
            @JsonProperty(value = "name", required = true) String name,
            @JsonProperty(value = "own_session", required = true) boolean ownSession) {}

    private static final ObjectMapper MAPPER = SigninConfig.strictMapper();

    /**
     * Reads and validates the file at p. Never throws: anything wrong is
     * {@link #DENY}, logged with the reason (never the file's content).
     */
    static ImpersonationFile load(Path p) {
        try {
            return parse(read(p));
        } catch (NoSuchFileException e) {
            LOG.warnf("portcullis: %s is missing: nobody can sign in as someone else until the Hub writes it", p);
        } catch (IOException | RuntimeException e) {
            LOG.errorf("portcullis: %s refused (%s): nobody can sign in as someone else until the Hub writes a valid one", p, clip(e));
        }
        return DENY;
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

    /**
     * Why the file was refused, without any value from it: a Jackson error's
     * class and JSON path (its message can quote the offending value — even
     * a reason), else this class's own message (field names and rules only).
     */
    /**
     * A Jackson error's JSON path with the file's own words left out: field
     * names of this class's records, array indexes, {@code {…}} for a map
     * key (a username) and for an unknown field's name.
     */
    private static String path(com.fasterxml.jackson.databind.JsonMappingException j) {
        StringBuilder b = new StringBuilder("$");
        List<com.fasterxml.jackson.databind.JsonMappingException.Reference> refs = j.getPath();
        for (int i = 0; i < refs.size(); i++) {
            com.fasterxml.jackson.databind.JsonMappingException.Reference r = refs.get(i);
            boolean last = i == refs.size() - 1;
            if (r.getIndex() >= 0) {
                b.append('[').append(r.getIndex()).append(']');
            } else if (r.getFrom() instanceof Map || (last && j instanceof com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException)
                    || r.getFieldName() == null || !r.getFieldName().matches("[a-z_]{1,16}")) {
                b.append(".{…}");
            } else {
                b.append('.').append(r.getFieldName());
            }
        }
        return b.toString();
    }

    static String clip(Throwable e) {
        Throwable c = e instanceof IOException && e.getCause() instanceof IllegalArgumentException ? e.getCause() : e;
        String m;
        if (c instanceof com.fasterxml.jackson.databind.JsonMappingException j) {
            m = j.getClass().getSimpleName() + " at " + path(j);
        } else if (c instanceof com.fasterxml.jackson.core.JsonProcessingException j) {
            m = j.getClass().getSimpleName() + (j.getLocation() == null ? ""
                    : " at line " + j.getLocation().getLineNr() + ", column " + j.getLocation().getColumnNr());
        } else if (c instanceof IllegalArgumentException) {
            m = Objects.toString(c.getMessage(), "");
        } else {
            m = c.getClass().getSimpleName();
        }
        m = m.replaceAll("\\p{Cntrl}", " ");
        return m.length() > 300 ? m.substring(0, 300) + "…" : m;
    }

    /** Decodes and validates raw; anything outside the contract's rules is an {@link IOException}. */
    static ImpersonationFile parse(byte[] raw) throws IOException {
        try {
            return decode(MAPPER.readValue(raw, FileJson.class));
        } catch (IllegalArgumentException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    private static ImpersonationFile decode(FileJson f) {
        if (f.version() != VERSION) {
            throw new IllegalArgumentException("version " + f.version() + ", want " + VERSION);
        }
        time(f.written(), "written");

        Set<String> clients = new LinkedHashSet<>();
        for (String c : f.clients()) {
            if (c == null || c.isEmpty() || c.length() > 255 || hasControl(c)) {
                throw new IllegalArgumentException("clients: an empty or unprintable client id");
            }
            clients.add(c);
        }

        Map<String, Pending> pending = new HashMap<>();
        for (PendingJson p : f.pending()) {
            if (p == null) {
                throw new IllegalArgumentException("pending: null");
            }
            String id = id(p.id(), "pending.id");
            if (p.adminSid() == null || !SESSION_ID.matcher(p.adminSid()).matches()) {
                throw new IllegalArgumentException("pending.admin_sid: not a session id");
            }
            if (!TOUCH_METHODS.contains(p.fresh())) {
                throw new IllegalArgumentException("pending.fresh: not a touch method");
            }
            Instant created = time(p.created(), "pending.created");
            Instant freshAt = time(p.freshAt(), "pending.fresh_at");
            if (freshAt.isAfter(created.plusSeconds(5))) {
                throw new IllegalArgumentException("pending.fresh_at: after created");
            }
            Pending v = new Pending(id, username(p.admin(), "pending.admin"), p.adminSid(), username(p.target(), "pending.target"),
                    reason(p.reason(), "pending.reason"), p.fresh(), freshAt, created, time(p.until(), "pending.until"));
            if (pending.put(id, v) != null) {
                throw new IllegalArgumentException("pending: an id twice");
            }
        }

        Map<String, SessionRec> sessions = new HashMap<>();
        for (SessionJson s : f.sessions()) {
            if (s == null) {
                throw new IllegalArgumentException("sessions: null");
            }
            String id = id(s.id(), "sessions.id");
            Instant ended;
            if (s.ended() == null || s.ended().isNull()) {
                ended = null;
            } else if (s.ended().isTextual()) {
                ended = time(s.ended().asText(), "sessions.ended");
            } else {
                throw new IllegalArgumentException("sessions.ended: neither null nor a time");
            }
            SessionRec v = new SessionRec(id, username(s.admin(), "sessions.admin"), username(s.target(), "sessions.target"),
                    reason(s.reason(), "sessions.reason"), time(s.started(), "sessions.started"), time(s.until(), "sessions.until"), ended);
            if (sessions.put(id, v) != null) {
                throw new IllegalArgumentException("sessions: an id twice");
            }
        }

        Map<String, List<Notice>> notices = new HashMap<>();
        for (Map.Entry<String, List<NoticeJson>> e : f.notices().entrySet()) {
            String user = username(e.getKey(), "notices: a key");
            if (e.getValue() == null) {
                throw new IllegalArgumentException("notices: null");
            }
            List<Notice> list = new ArrayList<>();
            for (NoticeJson n : e.getValue()) {
                if (n == null) {
                    throw new IllegalArgumentException("notices: null");
                }
                List<App> apps = new ArrayList<>();
                for (AppJson a : n.apps()) {
                    if (a == null || a.name() == null || a.name().isEmpty() || a.name().codePointCount(0, a.name().length()) > 200
                            || hasControlOrBidi(a.name())) {
                        throw new IllegalArgumentException("notices.apps: an empty or unprintable name");
                    }
                    apps.add(new App(a.name(), a.ownSession()));
                }
                list.add(new Notice(id(n.id(), "notices.id"), username(n.admin(), "notices.admin"), time(n.started(), "notices.started"),
                        time(n.ended(), "notices.ended"), reason(n.reason(), "notices.reason"), List.copyOf(apps)));
            }
            notices.put(user, List.copyOf(list));
        }

        return new ImpersonationFile(f.allowed(), Collections.unmodifiableSet(clients), Map.copyOf(pending), Map.copyOf(sessions),
                Map.copyOf(notices));
    }

    private static String id(String v, String what) {
        if (v == null || !ID.matcher(v).matches()) {
            throw new IllegalArgumentException(what + ": not 32 lowercase hex characters");
        }
        return v;
    }

    private static String username(String v, String what) {
        if (v == null || !USERNAME.matcher(v).matches()) {
            throw new IllegalArgumentException(what + ": not a username");
        }
        return v;
    }

    private static String reason(String v, String what) {
        if (!validReason(v)) {
            throw new IllegalArgumentException(what + ": not 3–200 characters on one line");
        }
        return v;
    }

    /** 3–200 runes, no control or bidi character (so one line). */
    static boolean validReason(String v) {
        if (v == null) {
            return false;
        }
        int n = v.codePointCount(0, v.length());
        return n >= 3 && n <= 200 && !hasControlOrBidi(v);
    }

    private static Instant time(String v, String what) {
        if (v == null) {
            throw new IllegalArgumentException(what + ": null");
        }
        try {
            return OffsetDateTime.parse(v, DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant();
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException(what + ": not RFC 3339");
        }
    }

    private static boolean hasControl(String s) {
        return s.codePoints().anyMatch(Character::isISOControl);
    }

    /** A control character (C0, DEL, C1, the line and paragraph separators) or a bidi control. */
    static boolean hasControlOrBidi(String s) {
        return s.codePoints().anyMatch(c -> Character.isISOControl(c) || c == 0x2028 || c == 0x2029 || c == 0x061c
                || c == 0x200e || c == 0x200f || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069));
    }

    // ── The cached current file ──

    /** The file at a path, re-read (and a failure logged) whenever its inode, mtime or size changes. */
    static final class Cache {
        private record Stamp(FileTime mtime, long size, Object fileKey) {}

        private final Path path;
        private Stamp stamp;
        private ImpersonationFile file = DENY;
        private boolean loaded;

        Cache(Path path) {
            this.path = path;
        }

        synchronized ImpersonationFile get() {
            Stamp now;
            try {
                BasicFileAttributes a = Files.readAttributes(path, BasicFileAttributes.class);
                now = new Stamp(a.lastModifiedTime(), a.size(), a.fileKey());
            } catch (IOException | RuntimeException e) {
                now = null;
            }
            if (loaded && Objects.equals(now, stamp)) {
                return file;
            }
            file = load(path); // logs why when it is DENY
            stamp = now;
            loaded = true;
            return file;
        }
    }

    private static final Cache CURRENT = new Cache(PATH);

    /** {@code /hub-data/impersonation.json}, cached by (inode, mtime, size); {@link #DENY} when missing or invalid. */
    static ImpersonationFile current() {
        return CURRENT.get();
    }
}
