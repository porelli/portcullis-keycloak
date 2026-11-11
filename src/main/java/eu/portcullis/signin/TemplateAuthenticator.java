package eu.portcullis.signin;

import jakarta.ws.rs.core.Response;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.Supplier;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * {@code portcullis-template} (contract §8.1 "Native-OIDC apps: exact, never
 * weaker"), REQUIRED at the end of the realm browser flow and of the Hub's
 * access-flow copies. The client's template ({@code signin-keycloak.json}
 * {@code clients}) must be met by the methods of this authentication
 * ({@link Methods#ofAuthentication}: the stock amr, kept only while each
 * method is on):
 *
 * <ul>
 * <li><b>met</b>, or an unlisted client with a valid file: success;</li>
 * <li><b>one completable method missing</b>: the flow runs again asking for
 * it, as if {@code pc_method} named it ({@link PcMethod#STEP_NOTE}), the
 * person and the executions completed so far kept, so an {@code all}
 * template is met step by step. Candidates as group-gate's step-up (§5):
 * for each alternative lacking exactly one method, that method — a passkey
 * kind only when the person has one (their Keycloak credentials), a password
 * or a YubiKey certificate (unknown) only when it can be completed here (a
 * password for an account that may use one; a certificate presented on this
 * request that Keycloak's X.509 mapping resolves to this person); the first
 * candidate not asked before in this authentication. Never inside a broker
 * flow (the setup link's post-broker login): there an unmet template shows
 * the page;</li>
 * <li><b>otherwise</b>: {@code portcullis-needs-stronger.ftl}, and the
 * sign-in goes no further: nothing is issued;</li>
 * <li><b>a missing, unreadable or invalid file</b> ({@code DENY_ALL}, or a
 * template the file doesn't hold): an error page for every client (a
 * challenge, so brute-force protection counts nothing); nobody signs in.</li>
 * </ul>
 *
 * <p>A step records the person's id ({@link #USER_NOTE}); the check fails
 * ({@code USER_CONFLICT}) when the authentication ends with anyone else.
 *
 * <p>It also writes {@link FreshMapper#NOTE}, the method that signed in
 * this authentication ({@code portcullis.passkey.kind},
 * {@code portcullis.x509.method} or {@code portcullis.password.method}; the
 * strongest by D1 strength while on when several ran — e.g. a password then
 * a step-up passkey; else {@code none}), as a client note: the only input of
 * {@code portcullis-fresh}.
 */
public class TemplateAuthenticator implements Authenticator {
    private static final Logger LOG = Logger.getLogger(TemplateAuthenticator.class);

    /** The form template (inside the jar's {@code theme-resources/templates}). */
    public static final String PAGE = "portcullis-needs-stronger.ftl";
    /** The form attribute holding {@link NeedsStronger}. */
    public static final String ATTRIBUTE = "portcullis";
    /** Methods already asked for in this authentication (comma-separated). */
    static final String ASKED_NOTE = "portcullis.template.asked";
    static final String NONE = "none";
    /** The id of the person a step was asked for. */
    static final String USER_NOTE = "portcullis.template.user";
    /** Message key of the page shown while the sign-in settings can't be read. */
    static final String UNAVAILABLE = "portcullisSignInUnavailable";

    /** Notes carried over a step's flow reset (Keycloak's reset clears every authentication note). */
    private static final List<String> KEPT_NOTES = List.of(PasskeyAuthenticator.KIND_NOTE, X509Authenticator.METHOD_NOTE, PasswordForm.METHOD_NOTE);

    private final Supplier<SigninConfig> config;

    public TemplateAuthenticator(Supplier<SigninConfig> config) {
        this.config = config;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        SigninConfig cfg = config.get();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        ClientModel client = authSession.getClient();
        String clientId = client == null ? null : client.getClientId();
        authSession.setClientNote(FreshMapper.NOTE, freshMethod(authSession, cfg));
        UserModel user = context.getUser();
        String stepUser = authSession.getAuthNote(USER_NOTE);
        if (stepUser != null && (user == null || !stepUser.equals(user.getId()))) {
            LOG.infof("portcullis: sign-in to %s refused: the account changed during a sign-in step", clientId);
            context.clearUser();
            context.getEvent().error(Errors.DIFFERENT_USER_AUTHENTICATED);
            context.failure(AuthenticationFlowError.USER_CONFLICT);
            return;
        }

        Optional<Rule> template = cfg.templateForClient(clientId);
        if (template.isEmpty()) {
            context.success(); // unlisted (and the file is valid): group-gate, mcp-gate or the Hub check it
            return;
        }
        Rule rule = template.get();
        if (rule.alternatives().isEmpty() || user == null) {
            LOG.infof("portcullis: sign-in to %s refused: no usable sign-in template", clientId);
            context.getEvent().error(Errors.ACCESS_DENIED);
            Response page = context.form().setError(UNAVAILABLE).createErrorPage(Response.Status.FORBIDDEN);
            context.forceChallenge(page);
            return;
        }
        Set<String> have = Methods.ofAuthentication(context.getRealm(), authSession, cfg);
        if (rule.satisfiedBy(have)) {
            context.success();
            return;
        }
        Set<String> setUp = setUp(user, cfg);
        Set<String> asked = asked(authSession);
        Predicate<String> completable = m -> switch (m) {
            case "password" -> !PasswordForm.refused(user.getUsername());
            case "yubikey_cert" -> certificateIsTheirs(context, user);
            default -> false;
        };
        boolean broker = inBrokerFlow(authSession);
        for (String m : broker ? List.<String>of() : candidates(rule, have, setUp, completable)) {
            if (!asked.contains(m)) {
                ask(context, m, asked);
                return;
            }
        }
        LOG.infof("portcullis: %s doesn't meet the sign-in template of %s", user.getUsername(), clientId);
        NeedsStronger page = NeedsStronger.of(cfg.clientName(clientId).orElse(clientId), have, rule.alternatives(),
                setUp, cfg.addStronger(), accountUrl(context));
        Response response = context.form().setAttribute(ATTRIBUTE, page).createForm(PAGE);
        context.forceChallenge(response);
    }

    /**
     * The step-up candidates (contract §5): for each alternative, in the
     * rule's order, that lacks exactly one method, that method — a passkey
     * kind when the person has set it up, any other method when
     * {@code completable} says it can be completed here.
     */
    static List<String> candidates(Rule rule, Set<String> have, Set<String> setUp, Predicate<String> completable) {
        List<String> out = new ArrayList<>();
        for (Set<String> alt : rule.alternatives()) {
            String missing = null;
            int count = 0;
            for (String m : alt) {
                if (!have.contains(m)) {
                    missing = m;
                    count++;
                }
            }
            if (count != 1 || out.contains(missing)) {
                continue;
            }
            boolean ok = Methods.PASSKEY_KINDS.contains(missing) ? setUp.contains(missing) : completable.test(missing);
            if (ok) {
                out.add(missing);
            }
        }
        return out;
    }

    /** The passkey kinds the person has set up (switched-on ones only). */
    static Set<String> setUp(UserModel user, SigninConfig cfg) {
        Set<String> out = new LinkedHashSet<>();
        for (String k : Methods.PASSKEY_KINDS) {
            if (cfg.on(k) && user.credentialManager().getStoredCredentialsByTypeStream(PasskeyClassifier.typeOf(k)).findAny().isPresent()) {
                out.add(k);
            }
        }
        return out;
    }

    private static Set<String> asked(AuthenticationSessionModel a) {
        Set<String> out = new LinkedHashSet<>();
        String v = a.getAuthNote(ASKED_NOTE);
        if (v != null && !v.isEmpty()) {
            for (String m : v.split(",")) {
                out.add(m);
            }
        }
        return out;
    }

    /**
     * Runs the flow again asking for method m: Keycloak's reset clears the
     * authentication's user, notes and execution statuses; the person, the
     * executions completed so far (the user-session notes, which carry the
     * amr) and the method notes are put back, and the ask is recorded so it
     * is never repeated.
     */
    private void ask(AuthenticationFlowContext context, String m, Set<String> asked) {
        AuthenticationSessionModel a = context.getAuthenticationSession();
        UserModel user = context.getUser();
        Map<String, String> userNotes = new HashMap<>(a.getUserSessionNotes());
        Map<String, String> kept = new HashMap<>();
        for (String n : KEPT_NOTES) {
            String v = a.getAuthNote(n);
            if (v != null) {
                kept.put(n, v);
            }
        }
        Set<String> next = new LinkedHashSet<>(asked);
        next.add(m);
        String askedValue = String.join(",", next);
        LOG.debugf("portcullis: %s needs %s for %s", user.getUsername(), m, a.getClient() == null ? null : a.getClient().getClientId());
        context.resetFlow(() -> {
            a.setAuthenticatedUser(user);
            userNotes.forEach(a::setUserSessionNote);
            kept.forEach(a::setAuthNote);
            a.setAuthNote(PcMethod.STEP_NOTE, m);
            a.setAuthNote(ASKED_NOTE, askedValue);
            a.setAuthNote(USER_NOTE, user.getId());
        });
    }

    /** The method that signed in this authentication (the strongest one, while on), else {@code none}. */
    static String freshMethod(AuthenticationSessionModel a, SigninConfig cfg) {
        String best = NONE;
        for (String n : KEPT_NOTES) {
            String m = a.getAuthNote(n);
            if (FreshMapper.isFreshMethod(m) && cfg.on(m) && (NONE.equals(best) || Methods.tenths(m) > Methods.tenths(best))) {
                best = m;
            }
        }
        return best;
    }

    /** Whether the authentication runs a broker flow (first or post broker login: no flow reset there). */
    static boolean inBrokerFlow(AuthenticationSessionModel a) {
        return a.getAuthNote(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT) != null
                || a.getAuthNote(AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE) != null;
    }

    /**
     * Whether this request presents a certificate that the flow's
     * {@code portcullis-x509} execution (its own X.509 config) maps to this
     * person; another person's certificate, or none, can't complete a step.
     */
    protected boolean certificateIsTheirs(AuthenticationFlowContext context, UserModel user) {
        AuthenticatorConfigModel x509 = x509Config(context);
        if (x509 == null) {
            return false;
        }
        return new X509Authenticator(false, config).certificateUser(context, x509)
                .map(u -> u.getId().equals(user.getId()))
                .orElse(false);
    }

    /** The config of the first {@code portcullis-x509} execution of this flow (sub-flows included). */
    static AuthenticatorConfigModel x509Config(AuthenticationFlowContext context) {
        RealmModel realm = context.getRealm();
        if (context.getTopLevelFlow() == null) {
            return null;
        }
        Deque<String> flows = new ArrayDeque<>(List.of(context.getTopLevelFlow().getId()));
        Set<String> seen = new HashSet<>();
        while (!flows.isEmpty()) {
            String flow = flows.pop();
            if (!seen.add(flow)) {
                continue;
            }
            for (AuthenticationExecutionModel e : realm.getAuthenticationExecutionsStream(flow).toList()) {
                if (e.isAuthenticatorFlow() && e.getFlowId() != null) {
                    flows.add(e.getFlowId());
                } else if (X509AuthenticatorFactory.PROVIDER_ID.equals(e.getAuthenticator()) && e.getAuthenticatorConfig() != null) {
                    return realm.getAuthenticatorConfigById(e.getAuthenticatorConfig());
                }
            }
        }
        return null;
    }

    /** The account console's signing-in page of this realm. */
    static String accountUrl(AuthenticationFlowContext context) {
        return KeycloakUriBuilder.fromUri(context.getUriInfo().getBaseUri())
                .path("realms/{realm}/account/account-security/signing-in")
                .build(context.getRealm().getName())
                .toString();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        authenticate(context);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void close() {}
}
