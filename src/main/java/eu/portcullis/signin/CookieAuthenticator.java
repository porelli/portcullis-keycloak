package eu.portcullis.signin;

import java.time.Instant;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * {@code auth-cookie}, overriding the stock provider (contract §8.1): the
 * stock SSO-cookie check, except that when {@code pc_method}
 * ({@link PcMethod}) names a method the SSO session lacks, it hands the
 * session to the sign-in flow like the stock step-up does — the user set,
 * the session's completed executions carried over (so its amr accumulates),
 * {@code attempted} — instead of signing in with the cookie alone.
 *
 * <p>The session's methods are {@link Methods#ofSession} (the stock amr,
 * kept only while each method is on). Without {@code pc_method}, without a
 * valid cookie, when the protocol asks for re-authentication, in a forked
 * flow, or when the session already has the method, the stock code runs
 * unchanged.
 *
 * <p>Whenever an SSO session is used — signed in with the cookie alone, or
 * handed to the sign-in flow — it sets the authentication note
 * {@link #SSO_NOTE}: {@code portcullis-template}'s history details tell
 * {@code sso} and {@code step_up} from a new sign-in by it (contract §8.1
 * "History details").
 *
 * <p>First of all, an impersonated identity cookie goes through
 * {@link ImpersonationGuard} (D42): allowed, it signs in with the cookie
 * alone (the stock code, which must succeed — anything else is refused);
 * refused or ended, the impersonating page goes out with
 * {@code forceChallenge} and nothing else runs.
 */
public class CookieAuthenticator extends org.keycloak.authentication.authenticators.browser.CookieAuthenticator {
    /** The authentication note: this authentication used an SSO session. */
    public static final String SSO_NOTE = "portcullis.sso";

    private final Supplier<SigninConfig> config;
    private final Supplier<ImpersonationFile> impersonations;
    private final Supplier<Instant> clock;
    private final Function<String, String> env;

    public CookieAuthenticator(Supplier<SigninConfig> config) {
        this(config, ImpersonationFile::current, Instant::now, System::getenv);
    }

    CookieAuthenticator(Supplier<SigninConfig> config, Supplier<ImpersonationFile> impersonations, Supplier<Instant> clock,
            Function<String, String> env) {
        this.config = config;
        this.impersonations = impersonations;
        this.clock = clock;
        this.env = env;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationManager.AuthResult[] seen = new AuthenticationManager.AuthResult[1];
        ImpersonationGuard.Ops ops = new ImpersonationGuard.Ops() {
            @Override
            public AuthenticationManager.AuthResult identity(AuthenticationFlowContext c) {
                seen[0] = cookie(c);
                return seen[0];
            }

            @Override
            public void logOut(AuthenticationFlowContext c, UserSessionModel us) {
                CookieAuthenticator.this.logOut(c, us);
            }

            @Override
            public jakarta.ws.rs.core.Response restart(AuthenticationFlowContext c, java.net.URI to) {
                return CookieAuthenticator.this.restart(c, to);
            }
        };
        Instant now = clock.get();
        ImpersonationGuard.Result guard = ImpersonationGuard.check(context, impersonations, now, ops, ImpersonationGuard.Stage.COOKIE);
        switch (guard.verdict()) {
            case REFUSE, ENDED -> {
                ImpersonationGuard.answer(context, guard, env, now, ops, ImpersonationGuard.Stage.COOKIE);
                return;
            }
            case ALLOW -> {
                stockNoted(context);
                if (context.getStatus() != FlowStatus.SUCCESS) {
                    // The cookie alone must sign in (an acr step-up, a forked flow …: never a new method).
                    ImpersonationGuard.answer(context, new ImpersonationGuard.Result(ImpersonationGuard.Verdict.REFUSE, guard.info(),
                            guard.person(), "the SSO cookie didn't sign in"), env, now, ops, ImpersonationGuard.Stage.COOKIE);
                }
                return;
            }
            default -> {
                // not impersonated: below
            }
        }
        Optional<String> requested = PcMethod.requested(context);
        if (requested.isEmpty()) {
            stockNoted(context);
            return;
        }
        AuthenticationManager.AuthResult sso = seen[0];
        if (sso == null || sso.session() == null || sso.user() == null) {
            context.attempted();
            return;
        }
        if (reauthenticate(context, sso) || PcMethod.metBy(requested.get(),
                Methods.ofSession(context.getRealm(), sso.session(), config.get()))) {
            stockNoted(context);
            return;
        }
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote(SSO_NOTE, "true");
        context.setUser(sso.user());
        AuthenticatorUtils.updateCompletedExecutions(authSession, sso.session(), context.getExecution().getId());
        context.attempted();
    }

    /** The stock authenticator; the note when the cookie signed in. */
    private void stockNoted(AuthenticationFlowContext context) {
        stock(context);
        if (context.getStatus() == FlowStatus.SUCCESS) {
            context.getAuthenticationSession().setAuthNote(SSO_NOTE, "true");
        }
    }

    /** The stock authenticator. */
    protected void stock(AuthenticationFlowContext context) {
        super.authenticate(context);
    }

    /** Logs out an impersonated session that isn't live (Keycloak's own logout in this request). */
    protected void logOut(AuthenticationFlowContext context, UserSessionModel us) {
        ImpersonationGuard.logOutNow(context, us);
    }

    /** The redirect that starts the authorize again (after an ended session's logout). */
    protected jakarta.ws.rs.core.Response restart(AuthenticationFlowContext context, java.net.URI to) {
        return ImpersonationGuard.restartResponse(to);
    }

    /** The SSO session of the identity cookie (null: none or invalid). */
    protected AuthenticationManager.AuthResult cookie(AuthenticationFlowContext context) {
        return AuthenticationManager.authenticateIdentityCookie(context.getSession(), context.getRealm(), true);
    }

    /** The stock reasons to ignore the cookie: re-authentication required, a forked flow. */
    protected boolean reauthenticate(AuthenticationFlowContext context, AuthenticationManager.AuthResult sso) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        if (AuthenticatorUtil.isForkedFlow(authSession)) {
            return true;
        }
        LoginProtocol protocol = context.getSession().getProvider(LoginProtocol.class, authSession.getProtocol());
        return protocol != null && protocol.requireReauthentication(sso.session(), authSession);
    }
}
