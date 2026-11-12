package eu.portcullis.signin;

import java.util.ArrayList;
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
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

/**
 * {@code portcullis-impersonation} (contract §8.1 "Impersonation", D40): for
 * a user session with {@link Impersonation#ID}, the claims
 * <ul>
 * <li>{@code act} = {@code {"sub": "<admin username>"}} (RFC 8693's actor);</li>
 * <li>{@code pc_imp} = {@code {"id": "<id>", "until": <epoch seconds>}}.</li>
 * </ul>
 * The claim names are fixed (a configured {@code claim.name} is ignored) and
 * the reason is never emitted. Partial notes (never written by
 * {@link ImpersonationResource}) give {@code pc_imp} with {@code until} 0 and
 * no {@code act}: malformed and past for every reader, so the token is
 * refused rather than passing as the person's own.
 */
public final class ImpersonationMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    public static final String PROVIDER_ID = "portcullis-impersonation";
    static final String ACT = "act";
    static final String PC_IMP = "pc_imp";

    private static final List<ProviderConfigProperty> PROPERTIES = properties();

    private static List<ProviderConfigProperty> properties() {
        List<ProviderConfigProperty> out = new ArrayList<>();
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(out, ImpersonationMapper.class);
        return List.copyOf(out);
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
        return PROPERTIES;
    }
}
