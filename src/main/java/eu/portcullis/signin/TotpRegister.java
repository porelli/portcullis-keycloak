package eu.portcullis.signin;

import jakarta.ws.rs.core.Response;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;
import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.requiredactions.UpdateTotp;
import org.keycloak.credential.CredentialModel;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * {@code CONFIGURE_TOTP} (contract §8.1 "Authenticator-app codes"): the stock
 * {@link UpdateTotp} — Keycloak makes the secret, shows the QR code and the
 * manual key, verifies the first code and stores the credential — behind
 * the checks before the stock code generates or stores anything: an
 * impersonated session (checked first here, so an administrator's session
 * never drops the person's pending setup), then {@link #decide} — the switch,
 * the reserved accounts, the add-stronger cap, at most {@link #MAX} apps and
 * the replace id.
 *
 * <ul>
 * <li><b>Replace</b> is {@code kc_action=CONFIGURE_TOTP:<credential uuid>}:
 * Keycloak 26.8.1 keeps the part after the first {@code :} as the client
 * note {@code kc_action_parameter}. A present parameter must be the id of one
 * of the person's own {@code otp} credentials; after the stock success the
 * named one is removed in the same transaction (gone by then: an exception,
 * the transaction rolls back and nothing is kept).</li>
 * <li><b>Refusals</b> of an application-initiated action (the client note
 * {@code kc_action} names {@code CONFIGURE_TOTP}) are a page with the
 * message and a link to the Sign-in page; the stock challenge never runs, so
 * no secret is generated. A refusal of the action as a <b>user</b> required
 * action (a setup link put it on the person) removes it from the person and
 * completes without storing anything, so it never repeats at every sign-in
 * (preflight P9). An impersonated session always gets
 * {@code portcullis-impersonating.ftl} mode refused (403), and the action is
 * never completed.</li>
 * <li><b>Success</b> adds {@code credential_user_label}, {@code credential_id}
 * and, on a replace, {@link #REPLACED} (the old label) to the stock
 * {@code UPDATE_CREDENTIAL} and puts the sign-in's history details back on
 * the builder ({@link History#reapply}). Keycloak sends that event once
 * {@code processAction} returns (checked live by the smoke run), and the
 * {@code LOGIN} that may follow in the same request uses the same builder,
 * so it carries them too, as it carries the stock {@code credential_type}.</li>
 * </ul>
 *
 * <p>It logs only the username, credential ids and the outcome: never the
 * secret, a code, the form or the {@code otpauth:} URI.
 */
public class TotpRegister extends UpdateTotp {
    private static final Logger LOG = Logger.getLogger(TotpRegister.class);

    /** At most this many authenticator apps per person (T18). */
    static final int MAX = 3;

    static final String ACTION = "CONFIGURE_TOTP";

    /** Message keys (the jar's {@code theme-resources/messages/messages_en.properties}). */
    static final String OFF = "portcullisTotpOff";
    static final String NOT_AVAILABLE = "portcullisTotpNotAvailable";
    static final String STRONGER = "portcullisTotpStrongerThanSession";
    static final String LIMIT = "portcullisTotpLimit";
    static final String REPLACE_UNKNOWN = "portcullisTotpReplaceUnknown";

    /** The refusal page (inside the jar's {@code theme-resources/templates}) and its attribute. */
    static final String PAGE = "portcullis-totp-refused.ftl";
    static final String ATTRIBUTE = "portcullis";

    /** The event details the override adds to {@code UPDATE_CREDENTIAL}. */
    static final String REPLACED = "pc_replaced";
    static final String CREDENTIAL_LABEL = Details.CREDENTIAL_USER_LABEL;
    static final String CREDENTIAL_ID = Details.CREDENTIAL_ID;

    /** The tenths a session needs to add a code without add_stronger (the code's own). */
    private static final int CODE_TENTHS = Methods.tenths(OtpAuthenticator.TOTP);

    /** What {@link #decide} answers: allowed (with the credential to replace, or null), or a refusal's message key. */
    record Decision(boolean allowed, String messageKey, String replaceId) {
        static Decision allow(String replaceId) {
            return new Decision(true, null, replaceId);
        }

        static Decision refuse(String messageKey) {
            return new Decision(false, messageKey, null);
        }
    }

    /** What the refusal page shows. */
    public static final class Refusal {
        private final String message;
        private final String signinUrl;

        Refusal(String message, String signinUrl) {
            this.message = message;
            this.signinUrl = signinUrl;
        }

        public String getMessage() {
            return message;
        }

        public String getSigninUrl() {
            return signinUrl;
        }
    }

    private final BiFunction<KeycloakSession, RealmModel, AuthenticationManager.AuthResult> identity;
    private final Function<String, String> env;
    private final java.util.function.Supplier<SigninConfig> config;

    public TotpRegister() {
        this((s, r) -> AuthenticationManager.authenticateIdentityCookie(s, r, true), System::getenv, SigninConfig::current);
    }

    TotpRegister(BiFunction<KeycloakSession, RealmModel, AuthenticationManager.AuthResult> identity, Function<String, String> env,
            java.util.function.Supplier<SigninConfig> config) {
        this.identity = identity;
        this.env = env;
        this.config = config;
    }

    // ── The rules (pure; tested on their own) ──

    /**
     * Whether a person may add (or, with replaceParam, replace) an
     * authenticator app now. sessionAmr: the session's raw amr values
     * ({@link PasskeyRegister#sessionAmr}); existing: their {@code otp}
     * credentials; replaceParam: the {@code kc_action_parameter} of a
     * {@code CONFIGURE_TOTP} action (empty: none); ownOtpIds: the ids of
     * their {@code otp} credentials. The impersonation check (third in the
     * contract's order) is the caller's: it needs the request.
     */
    static Decision decide(Set<String> sessionAmr, boolean addStronger, SigninConfig cfg, String username, int existing,
            Optional<String> replaceParam, Set<String> ownOtpIds) {
        if (cfg == null || !cfg.on(OtpAuthenticator.TOTP)) {
            return Decision.refuse(OFF);
        }
        if (username == null || PasswordForm.refused(username)) {
            return Decision.refuse(NOT_AVAILABLE);
        }
        Set<String> amr = sessionAmr == null ? Set.of() : sessionAmr;
        if (!addStronger && !amr.contains(PasskeyRegister.SETUP_LINK_AMR) && strongest(amr, cfg) < CODE_TENTHS) {
            return Decision.refuse(STRONGER);
        }
        Optional<String> replace = replaceParam == null ? Optional.empty() : replaceParam;
        if (replace.isPresent()) {
            String id = replace.get();
            if (ownOtpIds == null || id.isEmpty() || !ownOtpIds.contains(id)) {
                return Decision.refuse(REPLACE_UNKNOWN);
            }
            return Decision.allow(id); // a replace is allowed at the limit
        }
        if (existing >= MAX) {
            return Decision.refuse(LIMIT);
        }
        return Decision.allow(null);
    }

    /** The strongest switched-on method among the amr values, in tenths (0: none). */
    private static int strongest(Set<String> amr, SigninConfig cfg) {
        int best = 0;
        for (String a : amr) {
            Optional<String> m = Methods.forAmr(a).filter(cfg::on);
            if (m.isPresent()) {
                best = Math.max(best, Methods.tenths(m.get()));
            }
        }
        return best;
    }

    // ── The required action ──

    /** Whether this runs as the application-initiated action (the client note kc_action names it). */
    static boolean initiated(AuthenticationSessionModel auth) {
        String a = auth == null ? null : auth.getClientNote(Constants.KC_ACTION);
        return a != null && ACTION.equals(a.toUpperCase(Locale.ROOT));
    }

    /** The replace parameter of the application-initiated action (empty: none, or a user required action). */
    static Optional<String> replaceParam(AuthenticationSessionModel auth) {
        return initiated(auth) ? Optional.ofNullable(auth.getClientNote(Constants.KC_ACTION_PARAMETER)) : Optional.empty();
    }

    /** The ids of the user's otp credentials, in Keycloak's order. */
    static Set<String> otpIds(UserModel user) {
        Set<String> out = new LinkedHashSet<>();
        user.credentialManager().getStoredCredentialsByTypeStream(OtpAuthenticator.OTP_TYPE)
                .map(CredentialModel::getId)
                .forEach(out::add);
        return out;
    }

    /** decide over this request: the session, the file, the person and their credentials. */
    Decision decide(RequiredActionContext context) {
        SigninConfig cfg = config.get();
        if (cfg == null) {
            return Decision.refuse(OFF);
        }
        RealmModel realm = context.getRealm();
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        UserModel user = context.getUser();
        if (user == null) {
            return Decision.refuse(NOT_AVAILABLE);
        }
        UserSessionModel userSession = null;
        if (auth != null && auth.getParentSession() != null && context.getSession() != null && context.getSession().sessions() != null) {
            userSession = context.getSession().sessions().getUserSession(realm, auth.getParentSession().getId());
        }
        Set<String> ids = otpIds(user);
        return decide(PasskeyRegister.sessionAmr(realm, auth, userSession), cfg.addStronger(), cfg, user.getUsername(), ids.size(),
                replaceParam(auth), ids);
    }

    /**
     * The checks before the stock code: true when the request was answered
     * (a refusal, or a user required action dropped); false = go on with
     * decision's replace id in {@code replaceId[0]}.
     */
    private boolean refused(RequiredActionContext context, String[] replaceId) {
        UserModel user = context.getUser();
        String person = user == null ? null : user.getUsername();
        // Impersonated: refused whatever else holds, and never the P9 removal below (an
        // administrator's session never changes the person's own pending setup).
        Optional<Impersonation.Info> imp = ImpersonationGuard.impersonated(context.getSession(), context.getRealm(),
                context.getAuthenticationSession(), identity);
        if (imp.isPresent()) {
            refuseImpersonated(context, imp.get(), person);
            return true;
        }
        Decision d = decide(context);
        if (d.allowed()) {
            replaceId[0] = d.replaceId();
            return false;
        }
        if (!initiated(context.getAuthenticationSession())) {
            // P9: a setup link's action that can't run now never blocks every later sign-in.
            LOG.infof("portcullis: authenticator app setup for %s refused (%s): the required action is removed", person, d.messageKey());
            if (user != null) {
                user.removeRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
            }
            History.reapply(context);
            context.success();
            return true;
        }
        LOG.infof("portcullis: authenticator app setup for %s refused (%s)", person, d.messageKey());
        context.getEvent()
                .event(EventType.UPDATE_CREDENTIAL)
                .detail(Details.CREDENTIAL_TYPE, OtpAuthenticator.OTP_TYPE)
                .error(Errors.NOT_ALLOWED);
        String signin = TemplateAuthenticator.signinPage(env,
                () -> TemplateAuthenticator.accountUrl(context.getUriInfo().getBaseUri(), context.getRealm().getName()));
        context.challenge(context.form()
                .setAttribute(ATTRIBUTE, new Refusal(d.messageKey(), signin))
                .setStatus(Response.Status.FORBIDDEN)
                .createForm(PAGE));
        return true;
    }

    /** {@code portcullis-impersonating.ftl} mode refused (403): nothing stored, the action never completed. */
    private void refuseImpersonated(RequiredActionContext context, Impersonation.Info imp, String person) {
        LOG.infof("portcullis: impersonation %s: authenticator app setup refused", imp.id());
        context.getEvent()
                .event(EventType.UPDATE_CREDENTIAL)
                .detail(Details.CREDENTIAL_TYPE, OtpAuthenticator.OTP_TYPE)
                .detail(Details.REASON, "impersonated")
                .error(Errors.NOT_ALLOWED);
        String stop = Impersonation.stopUrl(env);
        LoginFormsProvider forms = context.form();
        ImpersonationBanner banner = ImpersonationBanner.of(imp, person, stop, Instant.now());
        if (banner != null) {
            forms.setAttribute(ImpersonationResource.BANNER, banner);
        }
        context.challenge(forms.setAttribute(ImpersonationResource.ATTRIBUTE, ImpersonatingPage.refused(person, stop))
                .setStatus(Response.Status.FORBIDDEN).createForm(ImpersonationResource.PAGE));
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        if (refused(context, new String[1])) {
            return;
        }
        stockChallenge(context);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        String[] replaceId = new String[1];
        if (refused(context, replaceId)) {
            return;
        }
        UserModel user = context.getUser();
        Set<String> before = otpIds(user);
        Set<String> added = new LinkedHashSet<>();
        stockProcess(onSuccess(context, () -> added.add(completed(context, user, before, replaceId[0]))));
        if (context.getStatus() != RequiredActionContext.Status.SUCCESS) {
            return; // a wrong code, a missing name: the stock form again, nothing stored
        }
        // Keycloak sends this builder's UPDATE_CREDENTIAL after processAction returns
        // (LoginActionsService.processRequireAction), so the details stay on it.
        History.reapply(context);
        if (replaceId[0] == null) {
            LOG.infof("portcullis: authenticator app added for %s: %s", user.getUsername(), String.join(",", added));
        } else {
            LOG.infof("portcullis: authenticator app replaced for %s: %s instead of %s", user.getUsername(), String.join(",", added), replaceId[0]);
        }
    }

    /**
     * Right before the stock {@code context.success()} (the credential is
     * stored; Keycloak sends {@code UPDATE_CREDENTIAL} right after it): the
     * new credential found, the replaced one removed, the details added; the
     * new id. Any surprise throws: the transaction rolls back, nothing kept.
     */
    private static String completed(RequiredActionContext context, UserModel user, Set<String> before, String replaceId) {
        CredentialModel created = null;
        int found = 0;
        for (CredentialModel c : user.credentialManager().getStoredCredentialsByTypeStream(OtpAuthenticator.OTP_TYPE).toList()) {
            if (!before.contains(c.getId())) {
                created = c;
                found++;
            }
        }
        if (found != 1) {
            throw new IllegalStateException("portcullis: the new authenticator app credential wasn't found");
        }
        EventBuilder e = context.getEvent();
        if (replaceId != null) {
            CredentialModel old = user.credentialManager().getStoredCredentialById(replaceId);
            if (old == null || !OtpAuthenticator.OTP_TYPE.equals(old.getType())
                    || !user.credentialManager().removeStoredCredentialById(replaceId)) {
                throw new IllegalStateException("portcullis: the authenticator app to replace is gone");
            }
            e.detail(REPLACED, old.getUserLabel() == null ? "" : old.getUserLabel());
        }
        e.detail(CREDENTIAL_LABEL, created.getUserLabel());
        e.detail(CREDENTIAL_ID, created.getId());
        return created.getId();
    }

    /** context, with hook run right before its {@code success()}. */
    static RequiredActionContext onSuccess(RequiredActionContext context, Runnable hook) {
        return (RequiredActionContext) Proxy.newProxyInstance(TotpRegister.class.getClassLoader(),
                new Class<?>[] {RequiredActionContext.class}, (p, m, args) -> {
                    if ("success".equals(m.getName()) && m.getParameterCount() == 0) {
                        hook.run();
                    }
                    try {
                        return m.invoke(context, args);
                    } catch (InvocationTargetException ex) {
                        throw ex.getCause();
                    }
                });
    }

    /** The stock challenge: the QR code and the manual key (the secret is made here). */
    void stockChallenge(RequiredActionContext context) {
        super.requiredActionChallenge(context);
    }

    /** The stock post: the first code verified, the credential stored. */
    void stockProcess(RequiredActionContext context) {
        super.processAction(context);
    }
}
