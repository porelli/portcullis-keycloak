package eu.portcullis.signin;

import java.util.List;
import java.util.function.Supplier;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * {@code portcullis-fresh} (contract §8.1), the protocol mapper of the
 * {@code portcullis-fresh-auth} client: the ID token claim {@code pc_fresh}
 * (a JSON string; the name is fixed, any {@code claim.name} config is
 * ignored) = the method id of the authenticator that signed the person in
 * in <b>this</b> authentication — a passkey kind, {@code yubikey_cert},
 * {@code browser_cert} or {@code password}, only while that method is on (the
 * strongest when several ran: {@code yubikey_cert > security_key >
 * passkey_device > browser_cert > passkey_synced > password}, the method
 * table's order — the certificate wins the 2.5 tie). Which methods approve
 * what is the Hub's check against the governing template (contract §8; the
 * Hub refuses {@code browser_cert} for certificates).
 *
 * <p>The value comes only from the client note {@link #NOTE}, which
 * {@code portcullis-template} writes at the end of every authentication from
 * that authentication's notes ({@code portcullis.passkey.kind},
 * {@code portcullis.x509.method}, {@code portcullis.password.method};
 * {@code none} otherwise, so an earlier
 * authentication's value never survives). Keycloak copies an authentication
 * session's client notes into the client session; authentication notes don't
 * reach the token endpoint. User-session notes and {@code amr} are never
 * read. A client session marked as signed in by the SSO cookie alone gets no
 * claim either, so {@code auth-cookie} (an SSO session reused) and the
 * setup-link flow never set it.
 */
public final class FreshMapper extends AbstractOIDCProtocolMapper implements OIDCIDTokenMapper {
    public static final String PROVIDER_ID = "portcullis-fresh";
    /** The claim, fixed. */
    public static final String CLAIM = "pc_fresh";
    /** The client note {@code portcullis-template} writes. */
    public static final String NOTE = "portcullis.fresh";

    private static final List<ProviderConfigProperty> PROPERTIES = properties();

    private static List<ProviderConfigProperty> properties() {
        List<ProviderConfigProperty> out = new java.util.ArrayList<>();
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(out, FreshMapper.class);
        return List.copyOf(out);
    }

    private final Supplier<SigninConfig> config;

    public FreshMapper() {
        this(SigninConfig::current);
    }

    FreshMapper(Supplier<SigninConfig> config) {
        this.config = config;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        AuthenticatedClientSessionModel clientSession = clientSessionCtx == null ? null : clientSessionCtx.getClientSession();
        if (clientSession == null || "true".equals(clientSession.getNote(AuthenticationManager.SSO_AUTH))) {
            return;
        }
        String m = clientSession.getNote(NOTE);
        if (isFreshMethod(m) && config.get().on(m)) {
            token.getOtherClaims().put(CLAIM, m);
        }
    }

    /**
     * Whether m is a method an authenticator of this authentication can write:
     * a passkey kind, {@code yubikey_cert}, {@code browser_cert} or
     * {@code password} (never {@code inv}).
     */
    static boolean isFreshMethod(String m) {
        return m != null && (Methods.PASSKEY_KINDS.contains(m) || X509Authenticator.YUBIKEY_CERT.equals(m)
                || X509Authenticator.BROWSER_CERT.equals(m) || PasswordForm.PASSWORD.equals(m));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Portcullis fresh sign-in";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "ID token claim pc_fresh: the passkey kind, yubikey_cert, browser_cert or password that signed in this authentication.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return PROPERTIES;
    }
}
