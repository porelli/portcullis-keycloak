package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

/** {@code portcullis-impersonation}: {@code act} and {@code pc_imp} from the user session's notes (D40). */
class ImpersonationMapperTest {
    static final String ID = ImpersonationFileTest.ID;

    /** Core's mapper: access token, ID token and userinfo; a claim.name that must be ignored. */
    private static ProtocolMapperModel model() {
        ProtocolMapperModel m = new ProtocolMapperModel();
        m.setName("impersonation");
        m.setProtocolMapper(ImpersonationMapper.PROVIDER_ID);
        m.setConfig(new HashMap<>(Map.of("id.token.claim", "true", "access.token.claim", "true",
                "userinfo.token.claim", "true", "claim.name", "other")));
        return m;
    }

    private static UserSessionModel session(Map<String, String> notes) {
        return Fake.named("user session").on("getNote", a -> notes.get((String) a[0])).as(UserSessionModel.class);
    }

    private static final ClientSessionContext CTX = Fake.named("ctx").as(ClientSessionContext.class);

    /** A token request's session: the client in the context (Keycloak's lightweight-token check reads it). */
    private static Flow flow() {
        Flow f = new Flow();
        f.contextFake.ret("getClient", Fake.named("client").ret("getClientId", "portcullis-forward-auth").as(org.keycloak.models.ClientModel.class));
        return f;
    }

    @Test
    void claimsWhenImpersonated() {
        Map<String, String> notes = Map.of(Impersonation.ID, ID, "IMPERSONATOR_USERNAME", "root",
                Impersonation.UNTIL, "1794494578", Impersonation.REASON, "checking quota");
        ImpersonationMapper m = new ImpersonationMapper();
        Flow f = flow();
        AccessToken access = m.transformAccessToken(new AccessToken(), model(), f.session, session(notes), CTX);
        IDToken id = m.transformIDToken(new IDToken(), model(), f.session, session(notes), CTX);
        AccessToken userinfo = m.transformUserInfoToken(new AccessToken(), model(), f.session, session(notes), CTX);
        for (IDToken t : new IDToken[] {access, id, userinfo}) {
            assertEquals(Map.of("sub", "root"), t.getOtherClaims().get("act"));
            assertEquals(Map.of("id", ID, "until", 1794494578L), t.getOtherClaims().get("pc_imp"));
            assertFalse(t.getOtherClaims().containsKey("other"));
            assertFalse(t.getOtherClaims().toString().contains("quota"), t.getOtherClaims().toString());
            assertFalse(t.getOtherClaims().containsKey("reason"));
        }

        // Partial notes: never a clean token — pc_imp alone (until 0) is malformed and past: every reader denies.
        IDToken partial = m.transformIDToken(new IDToken(), model(), f.session, session(Map.of(Impersonation.ID, ID)), CTX);
        assertFalse(partial.getOtherClaims().containsKey("act"));
        assertEquals(Map.of("id", ID, "until", 0L), partial.getOtherClaims().get("pc_imp"));
    }

    /**
     * I1: no knob switches the claims off — not the include-in-token flags,
     * not a client with lightweight access tokens, not introspection — and
     * the mapper offers no config at all.
     */
    @Test
    void claimsEvenWhenConfiguredOff() {
        Map<String, String> notes = Map.of(Impersonation.ID, ID, "IMPERSONATOR_USERNAME", "root",
                Impersonation.UNTIL, "1794494578", Impersonation.REASON, "checking quota");
        ProtocolMapperModel off = new ProtocolMapperModel();
        off.setName("impersonation");
        off.setProtocolMapper(ImpersonationMapper.PROVIDER_ID);
        off.setConfig(new HashMap<>(Map.of("id.token.claim", "false", "access.token.claim", "false",
                "userinfo.token.claim", "false", "introspection.token.claim", "false", "lightweight.claim", "false")));
        ProtocolMapperModel empty = new ProtocolMapperModel();
        empty.setProtocolMapper(ImpersonationMapper.PROVIDER_ID);
        empty.setConfig(new HashMap<>());
        Flow f = new Flow();
        f.contextFake.ret("getClient", Fake.named("lightweight client").ret("getClientId", "nextcloud")
                .on("getAttribute", a -> "client.use.lightweight.access.token.enabled".equals(a[0]) ? "true" : null)
                .as(org.keycloak.models.ClientModel.class));
        ImpersonationMapper m = new ImpersonationMapper();
        assertTrue(m.getConfigProperties().isEmpty());
        assertTrue(m instanceof org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper);
        for (ProtocolMapperModel model : new ProtocolMapperModel[] {off, empty}) {
            IDToken[] tokens = {
                m.transformAccessToken(new AccessToken(), model, f.session, session(notes), CTX),
                m.transformIDToken(new IDToken(), model, f.session, session(notes), CTX),
                m.transformUserInfoToken(new AccessToken(), model, f.session, session(notes), CTX),
                m.transformIntrospectionToken(new AccessToken(), model, f.session, session(notes), CTX)};
            for (IDToken t : tokens) {
                assertEquals(Map.of("sub", "root"), t.getOtherClaims().get("act"));
                assertEquals(Map.of("id", ID, "until", 1794494578L), t.getOtherClaims().get("pc_imp"));
            }
        }
    }

    @Test
    void nothingOtherwise() {
        ImpersonationMapper m = new ImpersonationMapper();
        Flow f = flow();
        // Keycloak's own notes alone (the stock feature) are not Portcullis' impersonation.
        Map<String, String> stock = Map.of("IMPERSONATOR_USERNAME", "root", "IMPERSONATOR_ID", "u-root");
        AccessToken t = m.transformAccessToken(new AccessToken(), model(), f.session, session(stock), CTX);
        assertFalse(t.getOtherClaims().containsKey("act"));
        assertFalse(t.getOtherClaims().containsKey("pc_imp"));
        assertFalse(t.getOtherClaims().containsKey("other"));
        IDToken none = m.transformIDToken(new IDToken(), model(), f.session, session(Map.of()), CTX);
        assertTrue(none.getOtherClaims().isEmpty());
    }
}
