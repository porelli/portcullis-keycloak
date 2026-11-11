package eu.portcullis.signin;

import java.util.ArrayList;
import java.util.List;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * {@code portcullis-x509}: see {@link X509Authenticator}. The stock X.509
 * settings plus {@link X509Authenticator#METHOD_CONFIG} and
 * {@link X509Authenticator#CA_CONFIG} (contract §8.1 "Flows").
 */
public final class X509AuthenticatorFactory extends X509ClientCertificateAuthenticatorFactory {
    public static final String PROVIDER_ID = "portcullis-x509";

    private static final List<ProviderConfigProperty> PROPERTIES = properties();

    private static List<ProviderConfigProperty> properties() {
        List<ProviderConfigProperty> out = new ArrayList<>();
        ProviderConfigProperty method = new ProviderConfigProperty();
        method.setName(X509Authenticator.METHOD_CONFIG);
        method.setLabel("Portcullis sign-in method");
        method.setType(ProviderConfigProperty.LIST_TYPE);
        method.setOptions(List.of(X509Authenticator.YUBIKEY_CERT, X509Authenticator.BROWSER_CERT));
        method.setHelpText("yubikey_cert (reference value mtls, the YubiKey certificate CA) or browser_cert "
                + "(reference value file, the browser certificate CA). Anything else: the execution never signs in.");
        out.add(method);
        ProviderConfigProperty ca = new ProviderConfigProperty();
        ca.setName(X509Authenticator.CA_CONFIG);
        ca.setLabel("Portcullis CA certificate file");
        ca.setType(ProviderConfigProperty.STRING_TYPE);
        ca.setHelpText("PEM file of the CA whose certificates this execution counts (issuer and signature). "
                + "Missing or unreadable: the execution never signs in.");
        out.add(ca);
        out.addAll(configProperties);
        return List.copyOf(out);
    }

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
        return "Portcullis YubiKey or browser certificate";
    }

    @Override
    public String getHelpText() {
        return "X.509 client certificate sign-in: one execution per kind (portcullis.method), only while that method is on "
                + "and the certificate was issued by its CA (portcullis.ca).";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return PROPERTIES;
    }
}
