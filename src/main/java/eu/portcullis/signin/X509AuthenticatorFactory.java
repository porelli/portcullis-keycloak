package eu.portcullis.signin;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;

/** {@code portcullis-x509}: see {@link X509Authenticator}. */
public final class X509AuthenticatorFactory extends X509ClientCertificateAuthenticatorFactory {
    public static final String PROVIDER_ID = "portcullis-x509";

    @Override
    public Authenticator create(KeycloakSession session) {
        return new X509Authenticator(isLegacyCriticalBehavior(), SigninConfig::current);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Portcullis YubiKey certificate";
    }

    @Override
    public String getHelpText() {
        return "X.509 client certificate sign-in, only while the YubiKey certificate method is on.";
    }
}
