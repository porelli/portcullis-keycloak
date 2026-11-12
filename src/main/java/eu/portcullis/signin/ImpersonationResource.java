package eu.portcullis.signin;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.CacheControl;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.function.Supplier;
import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.models.ImpersonationSessionNote;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.utils.AmrUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.util.JsonSerialization;

/**
 * {@code portcullis-impersonate} (contract §8.1 "Impersonation", D35, D38):
 * {@code GET /realms/<realm>/portcullis-impersonate/start?id=<id>}, opened
 * by the administrator's own browser after the Hub recorded the start.
 *
 * <p>The checks, in this order — any refusal is the page
 * {@code portcullis-impersonating.ftl} (mode {@code refused}, 403), logged
 * {@code portcullis: impersonation <id> refused: <why>}, and nothing is
 * created:
 * <ol>
 * <li>the file's {@code allowed};</li>
 * <li>a {@code pending} record with this id, {@code created} under 120 s
 * ago, its {@code sessions} record running for the same administrator and
 * person, and this its first use ({@code singleUseObjects().putIfAbsent});</li>
 * <li>the browser's identity cookie is the administrator's session
 * {@code admin_sid};</li>
 * <li>the administrator is in {@code lldap_admin};</li>
 * <li>the person exists and may be signed in as (enabled, no service
 * account, not {@code admin} / {@code portcullis-*}, not in
 * {@code lldap_admin}, not the administrator, no required action other than
 * the notice);</li>
 * <li>the methods: the administrator's plus the touch
 * ({@link #computeExecutions});</li>
 * <li>{@code PORTCULLIS_PORTAL_URL} is an http(s) URL.</li>
 * </ol>
 * Then, as Keycloak's own impersonation does in the same realm: the
 * administrator's session is logged out and its cookies expired, the
 * person's session is created with the notes, the login cookie set, the
 * event {@code IMPERSONATE} sent, and the browser goes to
 * {@code <auth base>/oauth2/start?rd=<portal>}. The reason is never logged,
 * put in the event or in a URL.
 */
public final class ImpersonationResource implements RealmResourceProvider {
    private static final Logger LOG = Logger.getLogger(ImpersonationResource.class);

    /** The page (inside the jar's {@code theme-resources/templates}). */
    public static final String PAGE = "portcullis-impersonating.ftl";
    /** The form attribute holding {@link ImpersonatingPage}. */
    public static final String ATTRIBUTE = "portcullis";
    /** The form attribute holding {@link ImpersonationBanner} (when the browser is in an impersonated session). */
    public static final String BANNER = "impersonation";
    /** Where the start sends the browser (core: {@code https://${PORTCULLIS_DOMAIN}/}). */
    static final String PORTAL_URL_ENV = "PORTCULLIS_PORTAL_URL";
    /** Keycloak's group of the LLDAP administrators. */
    static final String ADMIN_GROUP = PasskeyRegister.ADMIN_GROUP;
    /** The one required action the person may have. */
    static final String NOTICE_ACTION = "portcullis-impersonation-notice";
    /** How long a pending record can be used. */
    static final Duration PENDING_LIFE = Duration.ofSeconds(120);
    /** The single-use key's lifespan (longer than the pending record's). */
    static final long USED_SECONDS = 300;
    static final String USED_PREFIX = "pc_imp:";
    /** The user session's auth method (Keycloak's own impersonation uses {@code impersonate}). */
    static final String AUTH_METHOD = "portcullis-impersonate";
    /** Event details. */
    static final String DETAIL_ID = "pc_imp";
    static final String DETAIL_ACT = History.ACT;

    /** The Keycloak calls with side effects or request context (a test gives its own). */
    interface Ops {
        AuthenticationManager.AuthResult identity(KeycloakSession s, RealmModel r);

        void logOut(KeycloakSession s, RealmModel r, UserSessionModel admin);

        UserSessionModel create(KeycloakSession s, RealmModel r, UserModel target);

        void loginCookie(KeycloakSession s, RealmModel r, UserModel u, UserSessionModel us);

        EventBuilder event(KeycloakSession s, RealmModel r);

        /** The server's base URI ({@code https://auth.<domain>/}). */
        URI base(KeycloakSession s);
    }

    /** Keycloak's own calls, as {@code UserResource.impersonate} makes them (26.8.1). */
    static final Ops KEYCLOAK = new Ops() {
        @Override
        public AuthenticationManager.AuthResult identity(KeycloakSession s, RealmModel r) {
            return AuthenticationManager.authenticateIdentityCookie(s, r, true);
        }

        @Override
        public void logOut(KeycloakSession s, RealmModel r, UserSessionModel admin) {
            KeycloakContext c = s.getContext();
            AuthenticationManager.expireIdentityCookie(s);
            AuthenticationManager.expireRememberMeCookie(s);
            AuthenticationManager.expireAuthSessionCookie(s);
            AuthenticationManager.backchannelLogout(s, r, admin, c.getUri(), c.getConnection(), c.getHttpRequest().getHttpHeaders(), true);
        }

        @Override
        public UserSessionModel create(KeycloakSession s, RealmModel r, UserModel target) {
            return new UserSessionManager(s).createUserSession(r, target, target.getUsername(),
                    s.getContext().getConnection().getRemoteHost(), AUTH_METHOD, false, null, null);
        }

        @Override
        public void loginCookie(KeycloakSession s, RealmModel r, UserModel u, UserSessionModel us) {
            KeycloakContext c = s.getContext();
            AuthenticationManager.createLoginCookie(s, r, u, us, c.getUri(), c.getConnection());
        }

        @Override
        public EventBuilder event(KeycloakSession s, RealmModel r) {
            return new EventBuilder(r, s, s.getContext().getConnection());
        }

        @Override
        public URI base(KeycloakSession s) {
            return s.getContext().getUri().getBaseUri();
        }
    };

    /** The answer: a redirect (302 + location) or the page (403 + the rendered form). */
    record Outcome(int status, URI location, Response page) {}

    private final KeycloakSession session;
    private final Supplier<ImpersonationFile> file;
    private final Supplier<Instant> clock;
    private final Function<String, String> env;
    private final Ops ops;

    ImpersonationResource(KeycloakSession session) {
        this(session, ImpersonationFile::current, Instant::now, System::getenv, KEYCLOAK);
    }

    ImpersonationResource(KeycloakSession session, Supplier<ImpersonationFile> file, Supplier<Instant> clock,
            Function<String, String> env, Ops ops) {
        this.session = session;
        this.file = file;
        this.clock = clock;
        this.env = env;
        this.ops = ops;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {}

    @GET
    @Path("start")
    @Produces(MediaType.TEXT_HTML)
    public Response start(@QueryParam("id") String id) {
        Outcome o = begin(id);
        if (o.location() != null) {
            CacheControl none = new CacheControl();
            none.setNoStore(true);
            return Response.status(Response.Status.FOUND).location(o.location()).cacheControl(none).build();
        }
        return o.page();
    }

    /** The checks and the start; see the class comment. */
    Outcome begin(String id) {
        RealmModel realm = session.getContext().getRealm();
        boolean wellFormed = id != null && ImpersonationFile.ID.matcher(id).matches();
        String shown = wellFormed ? id : "-";
        ImpersonationFile f = file.get();
        Instant now = clock.get();
        if (!f.allowed()) {
            return refuse(shown, "signing in as someone else is switched off (or the file can't be read)", null);
        }
        if (!wellFormed) {
            return refuse(shown, "not an impersonation id", null);
        }
        Optional<ImpersonationFile.Pending> pending = f.pending(id);
        if (pending.isEmpty()) {
            return refuse(id, "no pending start with this id", null);
        }
        ImpersonationFile.Pending p = pending.get();
        if (!now.isBefore(p.created().plus(PENDING_LIFE)) || p.created().isAfter(now.plusSeconds(5))) {
            return refuse(id, "the pending start is older than 120 s", null);
        }
        Impersonation.Info info = new Impersonation.Info(id, p.admin(), p.reason(), p.until());
        if (!Impersonation.live(info, p.target(), f, now)) {
            return refuse(id, "no running record for this administrator and person", null);
        }
        if (!session.singleUseObjects().putIfAbsent(USED_PREFIX + id, USED_SECONDS)) {
            return refuse(id, "already used", null);
        }

        AuthenticationManager.AuthResult who = ops.identity(session, realm);
        if (who == null || who.session() == null || who.user() == null) {
            return refuse(id, "this browser has no Keycloak session", null);
        }
        UserSessionModel adminSession = who.session();
        UserModel admin = who.user();
        if (!p.adminSid().equals(adminSession.getId())) {
            return refuse(id, "this browser's session isn't the one the start was made from", adminSession);
        }
        if (!p.admin().equals(admin.getUsername())) {
            return refuse(id, "this browser's session isn't the administrator's", adminSession);
        }
        if (!inAdminGroup(admin)) {
            return refuse(id, p.admin() + " isn't in " + ADMIN_GROUP, adminSession);
        }

        UserModel target = session.users().getUserByUsername(realm, p.target());
        String why = targetRefusal(target, p);
        if (why != null) {
            return refuse(id, why, adminSession);
        }
        String executions = computeExecutions(realm, adminSession, p.fresh(), p.freshAt());
        if (executions == null) {
            return refuse(id, "the administrator's methods can't be carried over (no execution for " + p.fresh() + ")", adminSession);
        }
        URI next = next(ops.base(session), env);
        if (next == null) {
            return refuse(id, PORTAL_URL_ENV + " isn't an http(s) URL", adminSession);
        }

        ops.logOut(session, realm, adminSession);
        UserSessionModel us = ops.create(session, realm, target);
        us.setNote(ImpersonationSessionNote.IMPERSONATOR_ID.toString(), admin.getId());
        us.setNote(ImpersonationSessionNote.IMPERSONATOR_USERNAME.toString(), admin.getUsername());
        us.setNote(Impersonation.ID, id);
        us.setNote(Impersonation.UNTIL, String.valueOf(p.until().getEpochSecond()));
        us.setNote(Impersonation.REASON, p.reason());
        us.setNote(Constants.AUTHENTICATORS_COMPLETED, executions);
        ops.loginCookie(session, realm, target, us);
        ops.event(session, realm).event(EventType.IMPERSONATE).session(us).user(target)
                .detail(DETAIL_ID, id).detail(DETAIL_ACT, admin.getUsername()).success();
        LOG.infof("portcullis: impersonation %s started: %s signed in as %s until %s", id, admin.getUsername(),
                target.getUsername(), p.until());
        return new Outcome(302, next, null);
    }

    /** Why the person can't be signed in as, or null. */
    private static String targetRefusal(UserModel target, ImpersonationFile.Pending p) {
        if (target == null || !p.target().equals(target.getUsername())) {
            return "the person doesn't exist";
        }
        if (!target.isEnabled()) {
            return "the person is disabled";
        }
        if (target.getServiceAccountClientLink() != null) {
            return "the person is a service account";
        }
        String name = target.getUsername();
        if ("admin".equals(name) || name.startsWith("portcullis-")) {
            return "this account can't be signed in as";
        }
        if (inAdminGroup(target)) {
            return "the person is an administrator";
        }
        if (name.equals(p.admin())) {
            return "the administrator can't sign in as themselves";
        }
        List<String> other = target.getRequiredActionsStream().filter(a -> !NOTICE_ACTION.equals(a)).toList();
        if (!other.isEmpty()) {
            return "the person has an unfinished sign-in step";
        }
        return null;
    }

    private static boolean inAdminGroup(UserModel u) {
        return u.getGroupsStream().anyMatch(g -> ADMIN_GROUP.equals(g.getName()));
    }

    /** {@code <base>/oauth2/start?rd=<portal>}, or null when the portal env isn't an http(s) URL. */
    static URI next(URI base, Function<String, String> env) {
        String portal;
        try {
            portal = env.apply(PORTAL_URL_ENV);
        } catch (RuntimeException e) {
            return null;
        }
        if (portal == null || base == null) {
            return null;
        }
        portal = portal.trim();
        try {
            URI u = new URI(portal);
            if (!("https".equals(u.getScheme()) || "http".equals(u.getScheme())) || u.getHost() == null
                    || portal.chars().anyMatch(ch -> ch <= ' ' || ch == 0x7f)) {
                return null;
            }
        } catch (java.net.URISyntaxException e) {
            return null;
        }
        String b = base.toString();
        if (!b.endsWith("/")) {
            b += "/";
        }
        return URI.create(b + "oauth2/start?rd=" + URLEncoder.encode(portal, StandardCharsets.UTF_8));
    }

    /**
     * The person's session's {@code AUTHENTICATORS_COMPLETED} (call 5): the
     * administrator session's entries with their own times; when the amr of
     * the touch {@code fresh} isn't among them (within their max age, as
     * {@link AmrUtils} counts), plus the realm execution whose config's
     * {@code default.reference.value} is {@code Methods.amrOf(fresh)} (the
     * first by id), at {@code freshAt}. Null — refuse — when fresh isn't a
     * touch method, the note can't be read or there is no such execution.
     */
    static String computeExecutions(RealmModel r, UserSessionModel admin, String fresh, Instant freshAt) {
        if (r == null || admin == null || freshAt == null || !ImpersonationFile.TOUCH_METHODS.contains(fresh)) {
            return null;
        }
        Map<String, Integer> have;
        try {
            have = AuthenticatorUtils.parseCompletedExecutions(admin.getNote(Constants.AUTHENTICATORS_COMPLETED));
        } catch (RuntimeException e) {
            return null;
        }
        Map<String, Integer> out = new LinkedHashMap<>(have == null ? Map.of() : have);
        String amr = Methods.amrOf(fresh);
        if (!AmrUtils.getAuthenticationExecutionReferences(out, r).contains(amr)) {
            String execution = executionFor(r, amr);
            if (execution == null) {
                return null;
            }
            out.put(execution, (int) freshAt.getEpochSecond());
        }
        try {
            return JsonSerialization.writeValueAsString(out);
        } catch (IOException e) {
            return null;
        }
    }

    /** The id of the first (by id) execution of any realm flow whose config's reference value is amr. */
    private static String executionFor(RealmModel r, String amr) {
        TreeSet<String> found = new TreeSet<>();
        r.getAuthenticationFlowsStream().forEach(flow -> r.getAuthenticationExecutionsStream(flow.getId()).forEach(e -> {
            if (matches(r, e, amr)) {
                found.add(e.getId());
            }
        }));
        return found.isEmpty() ? null : found.first();
    }

    private static boolean matches(RealmModel r, AuthenticationExecutionModel e, String amr) {
        if (e == null || e.getId() == null || e.getAuthenticatorConfig() == null) {
            return false;
        }
        AuthenticatorConfigModel c = r.getAuthenticatorConfigById(e.getAuthenticatorConfig());
        return c != null && c.getConfig() != null && amr.equals(c.getConfig().get(Constants.AUTHENTICATION_EXECUTION_REFERENCE_VALUE));
    }

    /**
     * The refusal page (mode {@code refused}, 403), logged with the id and
     * why — never the reason. The banner shows when this browser's own
     * session is an impersonated one.
     */
    private Outcome refuse(String id, String why, UserSessionModel browserSession) {
        LOG.warnf("portcullis: impersonation %s refused: %s", id, why);
        String stop = Impersonation.stopUrl(env);
        LoginFormsProvider forms = session.getProvider(LoginFormsProvider.class);
        Optional<Impersonation.Info> mine = Impersonation.of(browserSession);
        ImpersonatingPage page;
        if (mine.isPresent() && browserSession.getUser() != null) {
            String person = browserSession.getUser().getUsername();
            page = ImpersonatingPage.refused(person, stop);
            ImpersonationBanner banner = ImpersonationBanner.of(mine.get(), person, stop, clock.get());
            if (banner != null) {
                forms.setAttribute(BANNER, banner);
            }
        } else {
            page = ImpersonatingPage.refusedStart(stop);
        }
        Response r = forms.setAttribute(ATTRIBUTE, page).setStatus(Response.Status.FORBIDDEN).createForm(PAGE);
        return new Outcome(403, null, r);
    }
}
