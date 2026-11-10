package eu.portcullis.signin;

import java.util.Map;
import java.util.function.Supplier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * {@code portcullis-method} (contract §8.1): config {@code method} plus the
 * reference value {@code default.reference.value}; succeeds only while that
 * method is on. It sits in the passkey sub-flow's per-kind conditional
 * sub-flows, where its reference value is the amr the session gets.
 *
 * <p>Fails closed ({@code ACCESS_DENIED}) on anything else: a missing or
 * unknown method, a reference value that isn't the method's amr, a method
 * that is off (including every method under {@code DENY_ALL}), and — for a
 * passkey kind — a passkey of another kind having signed in.
 */
public final class MethodAuthenticator implements Authenticator {
    /** The config key naming the method. */
    public static final String METHOD = "method";

    private final Supplier<SigninConfig> config;

    public MethodAuthenticator(Supplier<SigninConfig> config) {
        this.config = config;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (allowed(context)) {
            context.success();
        } else {
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
        }
    }

    private boolean allowed(AuthenticationFlowContext context) {
        AuthenticatorConfigModel model = context.getAuthenticatorConfig();
        Map<String, String> c = model == null ? null : model.getConfig();
        if (c == null) {
            return false;
        }
        String method = c.get(METHOD);
        if (!Methods.known(method) || !Methods.amrOf(method).equals(c.get(Constants.AUTHENTICATION_EXECUTION_REFERENCE_VALUE))) {
            return false;
        }
        if (!config.get().on(method)) {
            return false;
        }
        if (Methods.PASSKEY_KINDS.contains(method)) {
            String used = context.getAuthenticationSession() == null ? null
                    : context.getAuthenticationSession().getAuthNote(PasskeyAuthenticator.KIND_NOTE);
            return method.equals(used);
        }
        return true;
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
