package eu.portcullis.signin;

import java.util.Map;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * {@code portcullis-condition-passkey-kind} (contract §8.1, config
 * {@code kind}): true when the passkey that signed in this authentication
 * ({@link PasskeyAuthenticator#KIND_NOTE}) is of that kind. A missing or
 * unknown kind matches nothing. A condition that doesn't match skips its
 * sub-flow's {@code portcullis-method}, so the session gets no amr for it
 * (and {@code portcullis-passkey} itself never signs in a switched-off
 * kind).
 */
public final class PasskeyKindCondition implements ConditionalAuthenticator {
    /** The config key naming the kind. */
    public static final String KIND = "kind";

    static final PasskeyKindCondition SINGLETON = new PasskeyKindCondition();

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        AuthenticatorConfigModel model = context.getAuthenticatorConfig();
        Map<String, String> c = model == null ? null : model.getConfig();
        String kind = c == null ? null : c.get(KIND);
        if (kind == null || !Methods.PASSKEY_KINDS.contains(kind) || context.getAuthenticationSession() == null) {
            return false;
        }
        return kind.equals(context.getAuthenticationSession().getAuthNote(PasskeyAuthenticator.KIND_NOTE));
    }

    @Override
    public void action(AuthenticationFlowContext context) {}

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void close() {}

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }
}
