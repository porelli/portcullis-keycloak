package eu.portcullis.signin;

import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * What an impersonated session may do in Keycloak (contract §8.1
 * "Impersonation", D42, F13). In a browser whose identity cookie is an
 * impersonated session, an authentication goes ahead ({@link Verdict#ALLOW})
 * only when the session is live, the client is in the file's
 * {@code clients}, only the SSO cookie signed in (no method ran, no
 * {@code pc_method}, no {@code prompt=login}, {@code max_age} or acr
 * request), and the person has no required action other than the notice.
 * A session that isn't live is logged out ({@link Verdict#ENDED}); anything
 * else is {@link Verdict#REFUSE}. Both answers are
 * {@code portcullis-impersonating.ftl}, sent with {@code forceChallenge}.
 *
 * <p>{@code auth-cookie} checks at {@link Stage#COOKIE} (before it signs
 * in), {@code portcullis-template} at {@link Stage#TEMPLATE} (where the
 * cookie must have signed in alone, and the flow's own user session counts
 * too). Partial or inconsistent notes are never live: ENDED (review M4).
 * The reason is never logged.
 */
final class ImpersonationGuard {
    private static final Logger LOG = Logger.getLogger(ImpersonationGuard.class);

    private ImpersonationGuard() {}

    enum Verdict { NOT_IMPERSONATED, ALLOW, REFUSE, ENDED }

    /** Where the check runs: in {@code auth-cookie} (before the cookie signs in) or in {@code portcullis-template}. */
    enum Stage { COOKIE, TEMPLATE }

    /** The verdict, with the session's impersonation and the person (null when not impersonated), and why (for the log). */
    record Result(Verdict verdict, Impersonation.Info info, String person, String why) {
        static final Result NOT = new Result(Verdict.NOT_IMPERSONATED, null, null, null);
    }

    /** Keycloak's calls (a test gives its own). */
    interface Ops {
        /** The identity cookie's session (null: none or invalid). */
        AuthenticationManager.AuthResult identity(AuthenticationFlowContext c);

        /** Logs the session out (and the browser's identity cookie with it). */
        void logOut(AuthenticationFlowContext c, UserSessionModel us);
    }

    static final Ops KEYCLOAK = new Ops() {
        @Override
        public AuthenticationManager.AuthResult identity(AuthenticationFlowContext c) {
            return AuthenticationManager.authenticateIdentityCookie(c.getSession(), c.getRealm(), true);
        }

        @Override
        public void logOut(AuthenticationFlowContext c, UserSessionModel us) {
            logOutNow(c, us);
        }
    };

    /** Keycloak's own logout of us in this request (also its backchannel logout to the apps), the identity cookie expired. */
    static void logOutNow(AuthenticationFlowContext c, UserSessionModel us) {
        KeycloakSession s = c.getSession();
        KeycloakContext k = s.getContext();
        AuthenticationManager.expireIdentityCookie(s);
        AuthenticationManager.backchannelLogout(s, c.getRealm(), us, k.getUri(), k.getConnection(), k.getHttpRequest().getHttpHeaders(), true);
    }

    /** The one required action an impersonated person may have (the notice ignores impersonated sessions). */
    static final String NOTICE_ACTION = ImpersonationResource.NOTICE_ACTION;

    /**
     * The check (see the class comment). The file is read only when the
     * session is impersonated.
     */
    static Result check(AuthenticationFlowContext c, Supplier<ImpersonationFile> file, Instant now, Ops ops, Stage stage) {
        AuthenticationManager.AuthResult who = ops.identity(c);
        UserSessionModel us = who == null ? null : who.session();
        Optional<Impersonation.Info> imp = Impersonation.of(us);
        if (imp.isEmpty() && stage == Stage.TEMPLATE) {
            // The authentication's own user session (its root authentication session's), even without a valid cookie.
            UserSessionModel own = Impersonation.userSessionOf(c.getSession(), c.getRealm(), c.getAuthenticationSession(), c.getUser());
            Optional<Impersonation.Info> ownImp = Impersonation.of(own);
            if (ownImp.isPresent()) {
                us = own;
                imp = ownImp;
            }
        }
        if (imp.isEmpty()) {
            return Result.NOT;
        }
        Impersonation.Info info = imp.get();
        UserModel user = us.getUser();
        String person = user == null ? null : user.getUsername();
        ImpersonationFile f = file.get();
        if (!Impersonation.live(info, person, f, now)) {
            ops.logOut(c, us);
            return new Result(Verdict.ENDED, info, person, "not live");
        }
        String why = refusal(c, f, us, user, stage);
        return why == null ? new Result(Verdict.ALLOW, info, person, null) : new Result(Verdict.REFUSE, info, person, why);
    }

    /** Why a live impersonated session may not go ahead, or null. */
    private static String refusal(AuthenticationFlowContext c, ImpersonationFile f, UserSessionModel us, UserModel user, Stage stage) {
        AuthenticationSessionModel a = c.getAuthenticationSession();
        ClientModel client = a.getClient();
        if (client == null || !f.clients().contains(client.getClientId())) {
            return "a client not in the file's clients";
        }
        if (PcMethod.requested(c).isPresent()) {
            return "pc_method";
        }
        String prompt = a.getClientNote(OIDCLoginProtocol.PROMPT_PARAM);
        if (prompt != null && java.util.Arrays.asList(prompt.trim().split("\\s+")).contains(OIDCLoginProtocol.PROMPT_VALUE_LOGIN)) {
            return "prompt=login";
        }
        if (a.getClientNote(OIDCLoginProtocol.MAX_AGE_PARAM) != null) {
            return "max_age";
        }
        if (a.getClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION) != null
                || Boolean.parseBoolean(a.getClientNote(Constants.FORCE_LEVEL_OF_AUTHENTICATION))) {
            return "an acr request";
        }
        if (AuthenticatorUtil.isForkedFlow(a)) {
            return "a forked flow";
        }
        String kcAction = a.getClientNote(Constants.KC_ACTION);
        if (kcAction != null && !NOTICE_ACTION.equals(kcAction)) {
            return "an application-initiated action";
        }
        if (user == null || user.getRequiredActionsStream().anyMatch(r -> !NOTICE_ACTION.equals(r))
                || a.getRequiredActions().stream().anyMatch(r -> !NOTICE_ACTION.equals(r))) {
            return "a required action";
        }
        if (a.getAuthNote(PasskeyAuthenticator.KIND_NOTE) != null || a.getAuthNote(X509Authenticator.METHOD_NOTE) != null
                || a.getAuthNote(PasswordForm.METHOD_NOTE) != null) {
            return "a sign-in method ran";
        }
        if (stage == Stage.TEMPLATE) {
            if (a.getAuthNote(CookieAuthenticator.SSO_NOTE) == null) {
                return "the SSO cookie didn't sign in";
            }
            UserModel flowUser = c.getUser();
            if (flowUser == null || !flowUser.getId().equals(user.getId())) {
                return "another account signed in";
            }
            if (ranBeyondSession(c.getRealm(), a, us)) {
                return "a sign-in method ran";
            }
        }
        return null;
    }

    /**
     * Whether this authentication completed a method execution (one with a
     * reference value) the session hadn't: any authenticator, notes or not.
     * An unreadable note counts as one.
     */
    static boolean ranBeyondSession(RealmModel realm, AuthenticationSessionModel a, UserSessionModel us) {
        Map<String, Integer> mine;
        Map<String, Integer> session;
        try {
            mine = AuthenticatorUtils.parseCompletedExecutions(a.getUserSessionNotes().get(Constants.AUTHENTICATORS_COMPLETED));
            session = AuthenticatorUtils.parseCompletedExecutions(us.getNote(Constants.AUTHENTICATORS_COMPLETED));
        } catch (RuntimeException e) {
            return true;
        }
        for (String id : mine.keySet()) {
            if (session.containsKey(id)) {
                continue;
            }
            AuthenticationExecutionModel e = realm.getAuthenticationExecutionById(id);
            AuthenticatorConfigModel cfg = e == null || e.getAuthenticatorConfig() == null ? null
                    : realm.getAuthenticatorConfigById(e.getAuthenticatorConfig());
            if (e == null || (cfg != null && cfg.getConfig() != null
                    && cfg.getConfig().get(Constants.AUTHENTICATION_EXECUTION_REFERENCE_VALUE) != null)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Answers a REFUSE or ENDED result: {@code portcullis-impersonating.ftl}
     * (mode refused with the banner, or ended), 403, with
     * {@code forceChallenge} — {@code auth-cookie} is an ALTERNATIVE, and a
     * plain challenge would let the next alternative run. Logged with the id
     * and why, never the reason.
     */
    static void answer(AuthenticationFlowContext c, Result r, Function<String, String> env, Instant now) {
        ClientModel client = c.getAuthenticationSession().getClient();
        String clientId = client == null ? null : client.getClientId();
        if (r.verdict() == Verdict.ENDED) {
            LOG.infof("portcullis: impersonation %s ended: %s's session logged out (sign-in to %s)", r.info().id(), r.person(), clientId);
        } else {
            LOG.infof("portcullis: impersonation %s: sign-in to %s refused: %s", r.info().id(), clientId, r.why());
        }
        c.forceChallenge(page(c, r, env, now));
    }

    /** The page of a REFUSE or ENDED result. */
    static Response page(AuthenticationFlowContext c, Result r, Function<String, String> env, Instant now) {
        String stop = Impersonation.stopUrl(env);
        LoginFormsProvider forms = c.form();
        ImpersonatingPage page;
        if (r.verdict() == Verdict.ENDED) {
            page = ImpersonatingPage.ended(r.person(), stop);
        } else {
            page = ImpersonatingPage.refused(r.person(), stop);
            ImpersonationBanner banner = ImpersonationBanner.of(r.info(), r.person(), stop, now);
            if (banner != null) {
                forms.setAttribute(ImpersonationResource.BANNER, banner);
            }
        }
        return forms.setAttribute(ImpersonationResource.ATTRIBUTE, page).setStatus(Response.Status.FORBIDDEN)
                .createForm(ImpersonationResource.PAGE);
    }

    /**
     * For required actions, which have only a {@code RequiredActionContext}
     * (F13): the impersonation of the identity cookie's session, else of the
     * authentication's own user session; present (even with partial notes)
     * means impersonated.
     */
    static Optional<Impersonation.Info> impersonated(KeycloakSession s, RealmModel r, AuthenticationSessionModel a) {
        return impersonated(s, r, a, (ks, kr) -> AuthenticationManager.authenticateIdentityCookie(ks, kr, true));
    }

    static Optional<Impersonation.Info> impersonated(KeycloakSession s, RealmModel r, AuthenticationSessionModel a,
            BiFunction<KeycloakSession, RealmModel, AuthenticationManager.AuthResult> identity) {
        if (s == null || r == null) {
            return Optional.empty();
        }
        AuthenticationManager.AuthResult who = identity.apply(s, r);
        Optional<Impersonation.Info> i = Impersonation.of(who == null ? null : who.session());
        if (i.isPresent()) {
            return i;
        }
        return Impersonation.of(Impersonation.userSessionOf(s, r, a, a == null ? null : a.getAuthenticatedUser()));
    }
}
