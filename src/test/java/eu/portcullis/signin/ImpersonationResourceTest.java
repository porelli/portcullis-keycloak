package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.Constants;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * {@code portcullis-impersonate}'s start (contract §8.1 "Impersonation",
 * D38): every check before anything changes, then the person's session with
 * the administrator's methods plus the touch.
 */
class ImpersonationResourceTest {
    static final String ID = ImpersonationFileTest.ID;
    static final String REASON = "checking quota";
    static final Instant NOW = Instant.ofEpochSecond(Time.currentTimeSeconds());
    static final String PORTAL = "https://example.com/";

    /** One start: the realm, root (administrator, signed in with a YubiKey certificate) and alice. */
    static final class Start {
        final Flow f = new Flow();
        final Flow.Person root = f.person("u-root", "root");
        final Flow.Person alice = f.person("u-alice", "alice");
        final Map<String, String> rootNotes = new HashMap<>();
        final UserSessionModel rootSession;
        final Set<String> used = new HashSet<>();
        final Map<String, String> env = new HashMap<>(Map.of(ImpersonationResource.PORTAL_URL_ENV, PORTAL,
                TemplateAuthenticator.SIGNIN_URL_ENV, "https://people.example.com/signin"));
        final List<String> ops = new ArrayList<>();
        final Map<String, String> created = new HashMap<>();
        UserSessionModel createdSession;
        AuthenticationManager.AuthResult identity;
        final List<Map<String, Object>> events = new ArrayList<>();
        String fileJson;
        Instant created_ = NOW.minusSeconds(5);
        Instant freshAt = NOW.minusSeconds(10);
        final int t1 = (int) (Time.currentTimeSeconds() - 600);

        Start() {
            GroupModel admins = Fake.named("lldap_admin").ret("getName", "lldap_admin").as(GroupModel.class);
            root.fake.on("getGroupsStream", a -> Stream.of(admins));
            alice.fake.on("getRequiredActionsStream", a -> Stream.of());
            String mtls = f.execution("mtls");
            String hwk = f.execution("hwk");
            f.execution("pwd");
            f.flows.put("flow-browser", List.of(f.executions.get("exec-pwd"), f.executions.get(mtls), f.executions.get(hwk)));
            rootNotes.put(Constants.AUTHENTICATORS_COMPLETED, "{\"" + mtls + "\":" + t1 + "}");
            rootSession = Fake.named("root session").ret("getId", "sid-root").ret("getUser", root.model)
                    .on("getNote", a -> rootNotes.get((String) a[0]))
                    .as(UserSessionModel.class);
            identity = new AuthenticationManager.AuthResult(root.model, rootSession, null, null);
            SingleUseObjectProvider single = Fake.named("single use")
                    .on("putIfAbsent", a -> used.add((String) a[0]))
                    .as(SingleUseObjectProvider.class);
            f.sessionFake.ret("singleUseObjects", single);
            file(ID, "root", "sid-root", "alice");
        }

        void file(String id, String admin, String sid, String target) {
            fileJson = """
                {"version": 1, "allowed": true, "written": "%5$s", "clients": ["portcullis-forward-auth"],
                 "pending": [{"id": "%1$s", "admin": "%2$s", "admin_sid": "%3$s", "target": "%4$s", "reason": "%8$s",
                              "fresh": "security_key", "fresh_at": "%6$s", "created": "%5$s", "until": "%7$s"}],
                 "sessions": [{"id": "%1$s", "admin": "%2$s", "target": "%4$s", "reason": "%8$s",
                               "started": "%5$s", "until": "%7$s", "ended": null}],
                 "notices": {}}
                """.formatted(id, admin, sid, target, created_, freshAt, created_.plusSeconds(1800), REASON);
        }

        ImpersonationResource resource() {
            ImpersonationFile file;
            try {
                file = ImpersonationFile.parse(fileJson.getBytes(StandardCharsets.UTF_8));
            } catch (java.io.IOException e) {
                throw new IllegalStateException(e);
            }
            return new ImpersonationResource(f.session, () -> file, () -> NOW, env::get, new ImpersonationResource.Ops() {
                @Override
                public AuthenticationManager.AuthResult identity(KeycloakSession s, RealmModel r) {
                    ops.add("identity");
                    return identity;
                }

                @Override
                public void logOut(KeycloakSession s, RealmModel r, UserSessionModel admin) {
                    ops.add("logOut " + admin.getId());
                }

                @Override
                public UserSessionModel create(KeycloakSession s, RealmModel r, UserModel target) {
                    ops.add("create " + target.getUsername());
                    createdSession = Fake.named("alice session").ret("getId", "sid-alice").ret("getUser", target)
                            .on("getNote", a -> created.get((String) a[0]))
                            .on("setNote", a -> created.put((String) a[0], (String) a[1]))
                            .as(UserSessionModel.class);
                    return createdSession;
                }

                @Override
                public void loginCookie(KeycloakSession s, RealmModel r, UserModel u, UserSessionModel us) {
                    ops.add("loginCookie " + u.getUsername() + " " + us.getId());
                }

                @Override
                public EventBuilder event(KeycloakSession s, RealmModel r) {
                    return new EventBuilder(r, s) {
                        @Override
                        public void success() {
                            Map<String, Object> e = new HashMap<>();
                            e.put("type", getEvent().getType());
                            e.put("user", getEvent().getUserId());
                            e.put("session", getEvent().getSessionId());
                            e.put("details", getEvent().getDetails() == null ? Map.of() : new HashMap<>(getEvent().getDetails()));
                            events.add(e);
                        }

                        @Override
                        public void error(String error) {
                            events.add(Map.of("error", error));
                        }
                    };
                }

                @Override
                public URI base(KeycloakSession s) {
                    return URI.create("https://auth.example.com/");
                }
            });
        }

        ImpersonationResource.Outcome run() {
            return resource().begin(ID);
        }
    }

    @Test
    void startsSessionWithNotes() {
        Start s = new Start();
        ImpersonationResource.Outcome o = s.run();
        assertEquals(302, o.status(), String.valueOf(s.f.formAttributes));
        assertEquals(URI.create("https://auth.example.com/oauth2/start?rd=https%3A%2F%2Fexample.com%2F"), o.location());
        assertEquals(List.of("identity", "logOut sid-root", "create alice", "loginCookie alice sid-alice"), s.ops);
        assertEquals("u-root", s.created.get("IMPERSONATOR_ID"));
        assertEquals("root", s.created.get("IMPERSONATOR_USERNAME"));
        assertEquals(ID, s.created.get(Impersonation.ID));
        assertEquals(String.valueOf(s.created_.plusSeconds(1800).getEpochSecond()), s.created.get(Impersonation.UNTIL));
        assertEquals(REASON, s.created.get(Impersonation.REASON));
        assertNotNull(s.created.get(Constants.AUTHENTICATORS_COMPLETED));
        assertTrue(s.used.contains("pc_imp:" + ID));
        assertEquals(new Impersonation.Info(ID, "root", REASON, s.created_.plusSeconds(1800)),
                Impersonation.of(s.createdSession).orElseThrow());
    }

    @Test
    void methodsAreAdminsPlusFresh() {
        Start s = new Start();
        RealmModel r = s.f.realm;
        int t2 = (int) s.freshAt.getEpochSecond();
        String out = ImpersonationResource.computeExecutions(r, s.rootSession, "security_key", s.freshAt);
        assertEquals(Map.of("exec-mtls", s.t1, "exec-hwk", t2), AuthenticatorUtils.parseCompletedExecutions(out));

        // Already among the administrator's: copied unchanged, with its own time.
        int t0 = (int) (Time.currentTimeSeconds() - 1200);
        s.rootNotes.put(Constants.AUTHENTICATORS_COMPLETED, "{\"exec-mtls\":" + s.t1 + ",\"exec-hwk\":" + t0 + "}");
        out = ImpersonationResource.computeExecutions(r, s.rootSession, "security_key", s.freshAt);
        assertEquals(Map.of("exec-mtls", s.t1, "exec-hwk", t0), AuthenticatorUtils.parseCompletedExecutions(out));
        out = ImpersonationResource.computeExecutions(r, s.rootSession, "yubikey_cert", s.freshAt);
        assertEquals(Map.of("exec-mtls", s.t1, "exec-hwk", t0), AuthenticatorUtils.parseCompletedExecutions(out));

        // No execution with that reference: refused.
        s.f.flows.put("flow-browser", List.of(s.f.executions.get("exec-mtls")));
        s.rootNotes.put(Constants.AUTHENTICATORS_COMPLETED, "{\"exec-mtls\":" + s.t1 + "}");
        assertNull(ImpersonationResource.computeExecutions(r, s.rootSession, "security_key", s.freshAt));
        // Not a touch method, or an unreadable note: refused.
        assertNull(ImpersonationResource.computeExecutions(r, s.rootSession, "password", s.freshAt));
        assertNull(ImpersonationResource.computeExecutions(r, s.rootSession, "nonsense", s.freshAt));
        s.rootNotes.put(Constants.AUTHENTICATORS_COMPLETED, "{not json");
        assertNull(ImpersonationResource.computeExecutions(r, s.rootSession, "yubikey_cert", s.freshAt));

        // Through the start: the person's session holds exactly these.
        Start full = new Start();
        assertEquals(302, full.run().status());
        assertEquals(Map.of("exec-mtls", full.t1, "exec-hwk", (int) full.freshAt.getEpochSecond()),
                AuthenticatorUtils.parseCompletedExecutions(full.created.get(Constants.AUTHENTICATORS_COMPLETED)));
        assertEquals(Set.of("yubikey_cert", "security_key"), Methods.ofSession(full.f.realm, full.createdSession, Configs.plain()));
    }

    /** One refusal: the page, 403, nothing created, the administrator's session untouched. */
    private static void refused(String what, String why, Consumer<Start> setup) {
        Start s = new Start();
        setup.accept(s);
        ImpersonationResource.Outcome[] out = new ImpersonationResource.Outcome[1];
        List<String> log = captured(() -> out[0] = s.run());
        ImpersonationResource.Outcome o = out[0];
        assertTrue(log.stream().anyMatch(l -> l.contains(" refused: ") && l.contains(why)), what + ": " + log);
        assertEquals(403, o.status(), what);
        assertNull(o.location(), what);
        assertEquals(ImpersonationResource.PAGE, s.f.page, what);
        ImpersonatingPage page = (ImpersonatingPage) s.f.formAttributes.get(ImpersonationResource.ATTRIBUTE);
        assertEquals("refused", page.getMode(), what);
        assertTrue(s.ops.stream().noneMatch(op -> op.startsWith("logOut") || op.startsWith("create") || op.startsWith("loginCookie")),
                what + ": " + s.ops);
        assertNull(s.createdSession, what);
        assertTrue(s.events.isEmpty(), what);
    }

    @Test
    void refusals() {
        refused("not allowed", "switched off", s -> s.fileJson = s.fileJson.replace("\"allowed\": true", "\"allowed\": false"));
        refused("unknown id", "no pending start", s -> s.file(ImpersonationFileTest.OLD, "root", "sid-root", "alice"));
        refused("created 121 s ago", "older than 120 s", s -> {
            s.created_ = NOW.minusSeconds(121);
            s.file(ID, "root", "sid-root", "alice");
        });
        refused("the record ended", "no running record", s -> s.fileJson = s.fileJson.replace("\"ended\": null", "\"ended\": \"" + NOW + "\""));
        refused("second use", "already used", s -> s.used.add("pc_imp:" + ID));
        refused("no identity cookie", "no Keycloak session", s -> s.identity = null);
        refused("cookie session id ≠ admin_sid", "isn't the one the start was made from", s -> s.file(ID, "root", "sid-other", "alice"));
        refused("cookie user ≠ admin", "isn't the administrator's", s -> {
            Flow.Person sam = s.f.person("u-sam", "sam");
            GroupModel admins = Fake.named("lldap_admin").ret("getName", "lldap_admin").as(GroupModel.class);
            sam.fake.on("getGroupsStream", a -> Stream.of(admins));
            s.file(ID, "sam", "sid-root", "alice");
        });
        refused("admin not in lldap_admin", "isn't in lldap_admin", s -> s.root.fake.on("getGroupsStream", a -> Stream.of()));
        refused("target unknown", "doesn't exist", s -> s.file(ID, "root", "sid-root", "nobody"));
        refused("target disabled", "is disabled", s -> s.alice.fake.ret("isEnabled", false));
        refused("target a service account", "service account", s -> s.alice.fake.ret("getServiceAccountClientLink", "client-1"));
        refused("target portcullis-x", "can't be signed in as", s -> {
            Flow.Person x = s.f.person("u-x", "portcullis-x");
            x.fake.on("getRequiredActionsStream", a -> Stream.of());
            s.file(ID, "root", "sid-root", "portcullis-x");
        });
        refused("target admin", "can't be signed in as", s -> {
            Flow.Person x = s.f.person("u-admin", "admin");
            x.fake.on("getRequiredActionsStream", a -> Stream.of());
            s.file(ID, "root", "sid-root", "admin");
        });
        refused("target in lldap_admin", "is an administrator", s -> {
            GroupModel admins = Fake.named("lldap_admin").ret("getName", "lldap_admin").as(GroupModel.class);
            s.alice.fake.on("getGroupsStream", a -> Stream.of(admins));
        });
        refused("target == admin", "is an administrator", s -> {
            s.root.fake.on("getRequiredActionsStream", a -> Stream.of());
            s.file(ID, "root", "sid-root", "root");
        });
        refused("target has webauthn-register-passwordless", "unfinished sign-in step", s ->
                s.alice.fake.on("getRequiredActionsStream", a -> Stream.of("webauthn-register-passwordless")));
        refused("no execution for the touch", "can't be carried over", s -> s.f.flows.put("flow-browser", List.of(s.f.executions.get("exec-mtls"))));
        refused("PORTCULLIS_PORTAL_URL unset", "PORTCULLIS_PORTAL_URL", s -> s.env.remove(ImpersonationResource.PORTAL_URL_ENV));
        refused("PORTCULLIS_PORTAL_URL not http(s)", "PORTCULLIS_PORTAL_URL", s -> s.env.put(ImpersonationResource.PORTAL_URL_ENV, "javascript:alert(1)"));
        // The notice is the one required action allowed.
        Start ok = new Start();
        ok.alice.fake.on("getRequiredActionsStream", a -> Stream.of("portcullis-impersonation-notice"));
        assertEquals(302, ok.run().status());
    }

    @Test
    void notAnIdIsRefused() {
        Start s = new Start();
        ImpersonationResource.Outcome o = s.resource().begin("../x");
        assertEquals(403, o.status());
        assertTrue(s.ops.isEmpty());
        assertEquals(403, new Start().resource().begin(null).status());
    }

    @Test
    void impersonateEventHasIdAndActor() {
        Start s = new Start();
        s.run();
        assertEquals(1, s.events.size());
        Map<String, Object> e = s.events.get(0);
        assertEquals(EventType.IMPERSONATE, e.get("type"));
        assertEquals("u-alice", e.get("user"));
        assertEquals("sid-alice", e.get("session"));
        @SuppressWarnings("unchecked")
        Map<String, String> d = (Map<String, String>) e.get("details");
        assertEquals(ID, d.get("pc_imp"));
        assertEquals("root", d.get("pc_act"));
        assertFalse(d.toString().contains(REASON), d.toString());
    }

    @Test
    void logNeverHasReason() {
        List<String> lines = captured(() -> {
            new Start().run();
            refused("used", "already used", s -> s.used.add("pc_imp:" + ID));
            refused("cookie user ≠ admin", "isn't the administrator's", s -> s.identity = new AuthenticationManager.AuthResult(s.alice.model, s.rootSession, null, null));
            refused("unset portal", "PORTCULLIS_PORTAL_URL", s -> s.env.remove(ImpersonationResource.PORTAL_URL_ENV));
        });
        assertFalse(lines.isEmpty());
        assertTrue(lines.stream().anyMatch(l -> l.contains("portcullis: impersonation " + ID + " refused: ")), String.valueOf(lines));
        for (String l : lines) {
            assertFalse(l.contains(REASON), l);
            assertFalse(l.contains("quota"), l);
        }
    }

    /** Every line ImpersonationResource logs while r runs (all levels). */
    static List<String> captured(Runnable r) {
        java.util.logging.Logger jul = java.util.logging.Logger.getLogger(ImpersonationResource.class.getName());
        List<String> out = new ArrayList<>();
        Handler h = new Handler() {
            @Override
            public void publish(LogRecord rec) {
                out.add(String.valueOf(rec.getMessage()) + " " + java.util.Arrays.toString(rec.getParameters()));
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };
        Level before = jul.getLevel();
        jul.setLevel(Level.ALL);
        jul.addHandler(h);
        try {
            r.run();
        } finally {
            jul.removeHandler(h);
            jul.setLevel(before);
        }
        return out;
    }
}
