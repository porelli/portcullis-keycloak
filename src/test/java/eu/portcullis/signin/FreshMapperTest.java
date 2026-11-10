package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.IDToken;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * {@code pc_fresh}: portcullis-template writes this authentication's method
 * into the client note Keycloak copies into the client session; the mapper
 * reads only that.
 */
class FreshMapperTest {
    /** The Hub's mapper: name and type portcullis-fresh, ID token only, no claim.name. */
    private static ProtocolMapperModel model() {
        ProtocolMapperModel m = new ProtocolMapperModel();
        m.setName(FreshMapper.PROVIDER_ID);
        m.setProtocolMapper(FreshMapper.PROVIDER_ID);
        m.setConfig(new HashMap<>(Map.of("id.token.claim", "true", "access.token.claim", "false", "userinfo.token.claim", "false")));
        return m;
    }

    /** Ends the authentication (portcullis-template, an unlisted client) and issues an ID token. */
    private static IDToken issue(Flow f, SigninConfig cfg, Map<String, String> clientSessionNotes, Map<String, String> userSessionNotes) {
        f.clientId = "portcullis-fresh-auth";
        new TemplateAuthenticator(() -> cfg).authenticate(f.context);
        Map<String, String> notes = new HashMap<>(clientSessionNotes);
        notes.putAll(f.clientNotes); // Keycloak copies the authentication's client notes
        AuthenticatedClientSessionModel cs = Fake.named("client session")
                .on("getNote", a -> notes.get((String) a[0]))
                .as(AuthenticatedClientSessionModel.class);
        ClientSessionContext ctx = Fake.named("ctx").ret("getClientSession", cs).as(ClientSessionContext.class);
        UserSessionModel us = Fake.named("user session")
                .on("getNote", a -> userSessionNotes.get((String) a[0]))
                .as(UserSessionModel.class);
        IDToken token = new IDToken();
        new FreshMapper(() -> cfg).transformIDToken(token, model(), f.session, us, ctx);
        return token;
    }

    @Test
    void passkeyLoginGivesItsKind() {
        for (String kind : Methods.PASSKEY_KINDS) {
            Flow f = new Flow();
            f.authNotes.put(PasskeyAuthenticator.KIND_NOTE, kind);
            assertEquals(kind, issue(f, Configs.plain(), Map.of(), Map.of()).getOtherClaims().get(FreshMapper.CLAIM));
        }
    }

    @Test
    void certificateGivesYubikeyCert() {
        Flow f = new Flow();
        f.authNotes.put(X509Authenticator.METHOD_NOTE, "yubikey_cert");
        assertEquals("yubikey_cert", issue(f, Configs.plain(), Map.of(), Map.of()).getOtherClaims().get(FreshMapper.CLAIM));
        Flow both = new Flow(); // the stronger of the two
        both.authNotes.put(X509Authenticator.METHOD_NOTE, "yubikey_cert");
        both.authNotes.put(PasskeyAuthenticator.KIND_NOTE, "passkey_synced");
        assertEquals("yubikey_cert", issue(both, Configs.plain(), Map.of(), Map.of()).getOtherClaims().get(FreshMapper.CLAIM));
    }

    @Test
    void cookieOrPasswordGiveNoClaim() {
        // An earlier authentication's value in the client session is overwritten.
        Flow cookie = new Flow();
        assertFalse(issue(cookie, Configs.plain(), Map.of(FreshMapper.NOTE, "security_key"), Map.of())
                .getOtherClaims().containsKey(FreshMapper.CLAIM));
        Flow password = new Flow();
        password.completed("pwd");
        assertFalse(issue(password, Configs.of(Configs.WITH_PASSWORD, false, "", ""), Map.of(), Map.of())
                .getOtherClaims().containsKey(FreshMapper.CLAIM));
        // A client session the SSO cookie alone signed in gets no claim, whatever the note.
        Flow sso = new Flow();
        sso.authNotes.put(PasskeyAuthenticator.KIND_NOTE, "security_key");
        assertFalse(issue(sso, Configs.plain(), Map.of(AuthenticationManager.SSO_AUTH, "true"), Map.of())
                .getOtherClaims().containsKey(FreshMapper.CLAIM));
    }

    @Test
    void userSessionNoteIgnored() {
        Flow f = new Flow();
        Map<String, String> us = Map.of(PasskeyAuthenticator.KIND_NOTE, "security_key", FreshMapper.NOTE, "security_key",
                X509Authenticator.METHOD_NOTE, "yubikey_cert");
        assertFalse(issue(f, Configs.plain(), Map.of(), us).getOtherClaims().containsKey(FreshMapper.CLAIM));
    }

    @Test
    void switchedOffMethodGivesNoClaim() {
        Flow f = new Flow();
        f.authNotes.put(PasskeyAuthenticator.KIND_NOTE, "security_key");
        SigninConfig off = Configs.of("\"passkey_synced\"", false, "", "");
        assertFalse(issue(f, off, Map.of(), Map.of()).getOtherClaims().containsKey(FreshMapper.CLAIM));
        Flow deny = new Flow();
        deny.authNotes.put(PasskeyAuthenticator.KIND_NOTE, "security_key");
        assertFalse(issue(deny, SigninConfig.DENY_ALL, Map.of(), Map.of()).getOtherClaims().containsKey(FreshMapper.CLAIM));
    }
}
