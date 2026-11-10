package eu.portcullis.signin;

import java.util.List;
import java.util.Optional;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationSelectionOption;
import org.keycloak.models.UserModel;

/**
 * The sign-in page's "Try another way" choices (Keycloak shows the link when
 * the execution has more than one selection): only the methods this
 * authentication can use — the password form while {@code password} is on,
 * {@code pc_method} allows it and the known account may use one; the X.509
 * authenticator while {@code yubikey_cert} is on and allowed; a passkey
 * while a passkey kind is on and allowed. Anything else is kept.
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
        context.setAuthenticationSelections(options.stream()
                .filter(o -> usable(o.getAuthenticationExecution().getAuthenticator(), requested, known, cfg))
                .toList());
    }

    static boolean usable(String authenticator, Optional<String> requested, UserModel known, SigninConfig cfg) {
        if (PasswordFormFactory.PROVIDER_ID.equals(authenticator)) {
            return cfg.on(PasswordForm.PASSWORD) && PcMethod.allows(requested, PasswordForm.PASSWORD)
                    && (known == null || !PasswordForm.refused(known.getUsername()));
        }
        if (X509AuthenticatorFactory.PROVIDER_ID.equals(authenticator)) {
            return cfg.on(X509Authenticator.YUBIKEY_CERT) && PcMethod.allows(requested, X509Authenticator.YUBIKEY_CERT);
        }
        if (PasskeyAuthenticatorFactory.PROVIDER_ID.equals(authenticator)) {
            return Methods.PASSKEY_KINDS.stream().anyMatch(k -> cfg.on(k) && PcMethod.allows(requested, k));
        }
        return true;
    }
}
