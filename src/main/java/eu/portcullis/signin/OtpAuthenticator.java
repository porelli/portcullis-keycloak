package eu.portcullis.signin;

import java.util.function.BiFunction;
import java.util.function.Supplier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * {@code portcullis-otp} (contract §8.1 "Authenticator-app codes"): the stock
 * authenticator-app code form ({@link OTPFormAuthenticator}: Keycloak's own
 * verification, single-use store and brute-force counting), held, never
 * extended — it is <b>not</b> a {@code CredentialValidator}, so Keycloak's
 * selection keeps it in the flow's own order (the part-1 lesson, see
 * {@link PasskeyAuthenticator}).
 *
 * <ul>
 * <li>It never identifies a person: it steps aside ({@code attempted}) unless
 * all of {@link #steps} hold — {@code totp} is on, the user is already known
 * in this authentication (a {@code portcullis-template} step, a step-up, a
 * re-authentication), the user has an {@code otp} credential and isn't
 * {@code admin} / {@code portcullis-hub} ({@link PasswordForm#refused}),
 * {@code pc_method} is absent or {@code totp}, and the session isn't
 * impersonated (T13: the person's code is never asked for; {@code
 * portcullis-template} then shows its {@code needs} page). A code posted
 * meanwhile is never checked.</li>
 * <li>A posted code gets the history details {@code pc_method=totp} and
 * {@code pc_ua} first ({@link History#onFailure}), so the stock
 * {@code invalid_user_credentials} LOGIN_ERROR carries them.</li>
 * <li>A code that signs in writes {@link #TOTP} in the authentication note
 * {@link #METHOD_NOTE} ({@code portcullis-template} keeps it across a step
 * and folds it into {@code portcullis.fresh}).</li>
 * </ul>
 *
 * <p>It never logs the code or the secret.
 */
public class OtpAuthenticator implements Authenticator {
    /** The authentication note a code sign-in writes ({@link #TOTP}). */
    public static final String METHOD_NOTE = "portcullis.otp.method";
    /** The method id. */
    public static final String TOTP = "totp";
    /** Keycloak's credential type of an authenticator app ({@link OTPCredentialModel#TYPE}). */
    public static final String OTP_TYPE = OTPCredentialModel.TYPE;

    private final OTPFormAuthenticator stock = new OTPFormAuthenticator();
    private final Supplier<SigninConfig> config;
    /** The identity cookie's session (Keycloak's; a test gives its own). */
    private final BiFunction<KeycloakSession, RealmModel, AuthenticationManager.AuthResult> identity;

    public OtpAuthenticator(Supplier<SigninConfig> config) {
        this(config, (s, r) -> AuthenticationManager.authenticateIdentityCookie(s, r, true));
    }

    OtpAuthenticator(Supplier<SigninConfig> config, BiFunction<KeycloakSession, RealmModel, AuthenticationManager.AuthResult> identity) {
        this.config = config;
        this.identity = identity;
    }

    /**
     * Whether user may sign in with a code at all: {@code totp} on, not
     * {@code admin} / {@code portcullis-hub}, at least one {@code otp}
     * credential. Anything unreadable is false.
     */
    static boolean usable(UserModel user, SigninConfig cfg) {
        if (user == null || cfg == null || !cfg.on(TOTP) || PasswordForm.refused(user.getUsername())) {
            return false;
        }
        return hasCode(user);
    }

    /** Whether user has an {@code otp} credential (unreadable: false). */
    static boolean hasCode(UserModel user) {
        try {
            return user.credentialManager().getStoredCredentialsByTypeStream(OTP_TYPE).findAny().isPresent();
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Whether this authentication may ask for and check a code; false = {@code attempted}. */
    static boolean steps(AuthenticationFlowContext c, SigninConfig cfg) {
        return steps(c, cfg, (s, r) -> AuthenticationManager.authenticateIdentityCookie(s, r, true));
    }

    static boolean steps(AuthenticationFlowContext c, SigninConfig cfg,
            BiFunction<KeycloakSession, RealmModel, AuthenticationManager.AuthResult> identity) {
        if (c == null || !usable(c.getUser(), cfg) || !PcMethod.allows(PcMethod.requested(c), TOTP)) {
            return false;
        }
        try {
            return ImpersonationGuard.impersonated(c.getSession(), c.getRealm(), c.getAuthenticationSession(), identity).isEmpty();
        } catch (RuntimeException e) {
            return false; // unreadable: fail closed
        }
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        SigninConfig cfg = config.get();
        if (!steps(context, cfg, identity)) {
            context.attempted();
            return;
        }
        Offer.usableOnly(context, cfg);
        stock.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        if (!steps(context, config.get(), identity)) {
            context.attempted();
            return;
        }
        History.onFailure(context, TOTP); // pc_method / pc_ua on a LOGIN_ERROR
        stock.action(context);
        if (context.getStatus() == FlowStatus.SUCCESS) {
            context.getAuthenticationSession().setAuthNote(METHOD_NOTE, TOTP);
        }
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return usable(user, config.get());
    }

    /** Setup runs only through the {@code CONFIGURE_TOTP} override ({@link TotpRegister}). */
    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void close() {}
}
