package eu.portcullis.signin;

import java.security.cert.X509Certificate;
import java.util.function.Supplier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;

/**
 * {@code portcullis-x509} (contract §8.1): Keycloak's X.509 client
 * certificate authenticator (its own trust, validity, revocation and user
 * mapping checks, configured on the execution together with the reference
 * value {@code mtls}). It steps aside ({@code attempted}) while
 * {@code yubikey_cert} is off or when {@code pc_method} asks for another
 * method; a confirmation posted meanwhile fails. When it signs the person in
 * it puts {@code yubikey_cert} in the authentication note {@link #METHOD_NOTE}.
 */
public class X509Authenticator extends X509ClientCertificateAuthenticator {
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
        super.authenticate(context);
        noteSuccess(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        if (!usable(context)) {
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
            return;
        }
        super.action(context);
        noteSuccess(context);
    }

    private static void noteSuccess(AuthenticationFlowContext context) {
        if (context.getStatus() == FlowStatus.SUCCESS) {
            context.getAuthenticationSession().setAuthNote(METHOD_NOTE, YUBIKEY_CERT);
        }
    }

    /** Whether this request presents a client certificate (Keycloak's own lookup). */
    boolean presentsCertificate(AuthenticationFlowContext context) {
        try {
            X509Certificate[] chain = getCertificateChain(context);
            return chain != null && chain.length > 0;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
