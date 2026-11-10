package eu.portcullis.signin;

import java.util.Optional;
import java.util.function.Supplier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
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
 */
public class CookieAuthenticator extends org.keycloak.authentication.authenticators.browser.CookieAuthenticator {
    private final Supplier<SigninConfig> config;

    public CookieAuthenticator(Supplier<SigninConfig> config) {
        this.config = config;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Optional<String> requested = PcMethod.requested(context);
        if (requested.isEmpty()) {
            stock(context);
            return;
        }
        AuthenticationManager.AuthResult sso = cookie(context);
        if (sso == null || sso.session() == null || sso.user() == null) {
            context.attempted();
            return;
        }
        if (reauthenticate(context, sso) || PcMethod.metBy(requested.get(),
                Methods.ofSession(context.getRealm(), sso.session(), config.get()))) {
            stock(context);
            return;
        }
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        context.setUser(sso.user());
        AuthenticatorUtils.updateCompletedExecutions(authSession, sso.session(), context.getExecution().getId());
        context.attempted();
    }

    /** The stock authenticator. */
    protected void stock(AuthenticationFlowContext context) {
        super.authenticate(context);
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
