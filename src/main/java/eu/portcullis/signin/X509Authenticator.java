package eu.portcullis.signin;

import jakarta.ws.rs.core.Response;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.function.Supplier;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

/**
 * {@code portcullis-x509} (contract §8.1): Keycloak's X.509 client
 * certificate authenticator (its own trust, validity, revocation and user
 * mapping checks, configured on the execution together with the reference
 * value {@code mtls}). It steps aside ({@code attempted}) while
 * {@code yubikey_cert} is off or when {@code pc_method} asks for another
 * method; a confirmation posted meanwhile fails. When it signs the person in
 * it puts {@code yubikey_cert} in the authentication note {@link #METHOD_NOTE}.
 *
 * <p>A certificate never signs in another person than the one already known
 * in this authentication (a step-up, a {@code portcullis-template} step):
 * the user is compared by id after the stock code ran, and on a difference
 * cleared and the sign-in failed ({@code USER_CONFLICT}). Keycloak's
 * processor refuses the switch too, but the stock authenticator turns that
 * refusal into {@code attempted}.
 */
public class X509Authenticator extends X509ClientCertificateAuthenticator {
    private static final Logger LOG = Logger.getLogger(X509Authenticator.class);

    /** The authentication note naming the certificate method that signed in. */
    public static final String METHOD_NOTE = "portcullis.x509.method";

    static final String YUBIKEY_CERT = "yubikey_cert";

    private final Supplier<SigninConfig> config;

    public X509Authenticator(boolean legacyCriticalBehavior, Supplier<SigninConfig> config) {
        super(legacyCriticalBehavior);
        this.config = config;
    }

    private boolean usable(AuthenticationFlowContext context) {
        return config.get().on(YUBIKEY_CERT) && PcMethod.allows(PcMethod.requested(context), YUBIKEY_CERT);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (!usable(context)) {
            context.attempted();
            return;
        }
        UserModel known = context.getUser();
        super.authenticate(context);
        if (sameUser(context, known)) {
            noteSuccess(context);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        if (!usable(context)) {
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
            return;
        }
        UserModel known = context.getUser();
        super.action(context);
        if (sameUser(context, known)) {
            noteSuccess(context);
        }
    }

    /** False (and the sign-in failed, the user cleared) when the certificate's user isn't the one known before. */
    private static boolean sameUser(AuthenticationFlowContext context, UserModel known) {
        UserModel now = context.getUser();
        if (known == null || (now != null && known.getId().equals(now.getId()))) {
            return true;
        }
        LOG.infof("portcullis: a certificate of another account was presented while %s was signing in", known.getUsername());
        context.clearUser();
        context.getEvent().error(Errors.DIFFERENT_USER_AUTHENTICATED);
        Response page = context.form().setError(Messages.WEBAUTHN_ERROR_DIFFERENT_USER)
                .createErrorPage(Response.Status.UNAUTHORIZED);
        context.failure(AuthenticationFlowError.USER_CONFLICT, page);
        return false;
    }

    private static void noteSuccess(AuthenticationFlowContext context) {
        if (context.getStatus() == FlowStatus.SUCCESS) {
            context.getAuthenticationSession().setAuthNote(METHOD_NOTE, YUBIKEY_CERT);
        }
    }

    /**
     * The account the certificate this request presents maps to, with the
     * execution's own X.509 config (Keycloak's identity extractor and user
     * mapper); empty when there is none or it maps to nobody. The trust and
     * revocation checks run when the authenticator itself signs it in.
     */
    Optional<UserModel> certificateUser(AuthenticationFlowContext context, AuthenticatorConfigModel model) {
        try {
            if (model == null || model.getConfig() == null) {
                return Optional.empty();
            }
            X509Certificate[] chain = getCertificateChain(context);
            if (chain == null || chain.length == 0) {
                return Optional.empty();
            }
            X509AuthenticatorConfigModel config = new X509AuthenticatorConfigModel(model);
            Object identity = getUserIdentityExtractor(config).extractUserIdentity(chain);
            return identity == null ? Optional.empty()
                    : Optional.ofNullable(getUserIdentityToModelMapper(config).find(context, identity));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
