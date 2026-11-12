package eu.portcullis.signin;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

/**
 * {@code portcullis-impersonation} (contract §8.1 "Impersonation", D40): for
 * a user session with {@link Impersonation#ID}, the claims
 * <ul>
 * <li>{@code act} = {@code {"sub": "<admin username>"}} (RFC 8693's actor);</li>
 * <li>{@code pc_imp} = {@code {"id": "<id>", "until": <epoch seconds>}}.</li>
 * </ul>
 * The claim names are fixed (a configured {@code claim.name} is ignored) and
 * the reason is never emitted. Nothing switches them off: the access token,
 * the ID token, userinfo and introspection always carry them (the
 * include-in-token flags and lightweight access tokens are not read, and the
 * mapper has no config), so an impersonated session's token never passes as
 * the person's own. Partial notes (never written by
 * {@link ImpersonationResource}) give {@code pc_imp} with {@code until} 0 and
 * no {@code act}: malformed and past for every reader, so the token is
 * refused rather than passing as the person's own.
 */
public final class ImpersonationMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper, TokenIntrospectionTokenMapper {
    public static final String PROVIDER_ID = "portcullis-impersonation";
    static final String ACT = "act";
    static final String PC_IMP = "pc_imp";

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        setClaim(token, mappingModel, userSession, session, clientSessionCtx);
        return token;
    }

    @Override
    public IDToken transformIDToken(IDToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        setClaim(token, mappingModel, userSession, session, clientSessionCtx);
        return token;
    }

    @Override
    public AccessToken transformUserInfoToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        setClaim(token, mappingModel, userSession, session, clientSessionCtx);
        return token;
    }

    @Override
    public AccessToken transformIntrospectionToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        setClaim(token, mappingModel, userSession, session, clientSessionCtx);
        return token;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        Optional<Impersonation.Info> i = Impersonation.of(userSession);
        if (i.isEmpty()) {
            return;
        }
        Impersonation.Info info = i.get();
        Map<String, Object> imp = new LinkedHashMap<>();
        imp.put("id", info.id());
        imp.put("until", info.until() == null ? 0L : info.until().getEpochSecond());
        token.getOtherClaims().put(PC_IMP, imp);
        if (info.admin() != null) {
            token.getOtherClaims().put(ACT, Map.of("sub", info.admin()));
        }
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Portcullis impersonation";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Claims act {sub} and pc_imp {id, until} for a session an administrator started as this person; nothing otherwise.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}
