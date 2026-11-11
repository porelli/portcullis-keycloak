package eu.portcullis.signin;

import java.util.List;
import java.util.Optional;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationSelectionOption;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * The sign-in page's "Try another way" choices (Keycloak shows the link when
 * the execution has more than one selection): only the methods this
 * authentication can use — the password form while {@code password} is on,
 * {@code pc_method} allows it and the known account may use one; each X.509
 * execution while its own method (its config's {@code portcullis.method}:
 * {@code yubikey_cert} or {@code browser_cert}) is on and allowed, never one
 * without a known method; a passkey while a passkey kind is on and allowed.
 * Anything else is kept.
 */
final class Offer {
    private Offer() {}

    static void usableOnly(AuthenticationFlowContext context, SigninConfig cfg) {
        List<AuthenticationSelectionOption> options = context.getAuthenticationSelections();
        if (options == null || options.isEmpty()) {
            return;
        }
        Optional<String> requested = PcMethod.requested(context);
        UserModel known = context.getUser();
        RealmModel realm = context.getRealm();
        context.setAuthenticationSelections(options.stream()
                .filter(o -> usable(realm, o.getAuthenticationExecution(), requested, known, cfg))
                .toList());
    }

    static boolean usable(RealmModel realm, AuthenticationExecutionModel e, Optional<String> requested, UserModel known, SigninConfig cfg) {
        String authenticator = e == null ? null : e.getAuthenticator();
        if (PasswordFormFactory.PROVIDER_ID.equals(authenticator)) {
            return cfg.on(PasswordForm.PASSWORD) && PcMethod.allows(requested, PasswordForm.PASSWORD)
                    && (known == null || !PasswordForm.refused(known.getUsername()));
        }
        if (X509AuthenticatorFactory.PROVIDER_ID.equals(authenticator)) {
            String m = X509Authenticator.method(config(realm, e));
            return m != null && cfg.on(m) && PcMethod.allows(requested, m);
        }
        if (PasskeyAuthenticatorFactory.PROVIDER_ID.equals(authenticator)) {
            return Methods.PASSKEY_KINDS.stream().anyMatch(k -> cfg.on(k) && PcMethod.allows(requested, k));
        }
        return true;
    }

    private static AuthenticatorConfigModel config(RealmModel realm, AuthenticationExecutionModel e) {
        if (realm == null || e.getAuthenticatorConfig() == null) {
            return null;
        }
        try {
            return realm.getAuthenticatorConfigById(e.getAuthenticatorConfig());
        } catch (RuntimeException ex) {
            return null;
        }
    }
}
