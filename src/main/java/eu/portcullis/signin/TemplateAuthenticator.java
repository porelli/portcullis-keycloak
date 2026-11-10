package eu.portcullis.signin;

import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.HashMap;
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
import org.keycloak.common.util.KeycloakUriBuilder;
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
 * request); the first candidate not asked before in this authentication;</li>
 * <li><b>otherwise</b>: {@code portcullis-needs-stronger.ftl}, and the
 * sign-in goes no further: nothing is issued;</li>
 * <li><b>a missing, unreadable or invalid file</b> ({@code DENY_ALL}, or a
 * template the file doesn't hold): failure for every client.</li>
 * </ul>
 *
 * <p>It also writes {@link FreshMapper#NOTE}, the method that signed in
 * this authentication ({@code portcullis.passkey.kind} or
 * {@code portcullis.x509.method}, the stronger while on; else {@code none}),
 * as a client note: the only input of {@code portcullis-fresh}.
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

    /** Notes carried over a step's flow reset (Keycloak's reset clears every authentication note). */
    private static final List<String> KEPT_NOTES = List.of(PasskeyAuthenticator.KIND_NOTE, X509Authenticator.METHOD_NOTE);

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

        Optional<Rule> template = cfg.templateForClient(clientId);
        if (template.isEmpty()) {
            context.success(); // unlisted (and the file is valid): group-gate, mcp-gate or the Hub check it
            return;
        }
        Rule rule = template.get();
        UserModel user = context.getUser();
        if (rule.alternatives().isEmpty() || user == null) {
            LOG.infof("portcullis: sign-in to %s refused: no usable sign-in template", clientId);
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
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
            case "yubikey_cert" -> presentsCertificate(context);
            default -> false;
        };
        for (String m : candidates(rule, have, setUp, completable)) {
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
        });
    }

    /** The method that signed in this authentication (the stronger one, while on), else {@code none}. */
    static String freshMethod(AuthenticationSessionModel a, SigninConfig cfg) {
        String best = NONE;
        for (String n : KEPT_NOTES) {
            String m = a.getAuthNote(n);
            boolean fresh = m != null && (Methods.PASSKEY_KINDS.contains(m) || X509Authenticator.YUBIKEY_CERT.equals(m));
            if (fresh && cfg.on(m) && (NONE.equals(best) || Methods.tenths(m) > Methods.tenths(best))) {
                best = m;
            }
        }
        return best;
    }

    /** Whether this request presents a client certificate (Keycloak's X.509 lookup). */
    protected boolean presentsCertificate(AuthenticationFlowContext context) {
        return new X509Authenticator(false, config).presentsCertificate(context);
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
