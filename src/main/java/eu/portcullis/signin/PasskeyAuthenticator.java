package eu.portcullis.signin;

import jakarta.ws.rs.core.MultivaluedMap;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.browser.WebAuthnMetadataService;
import org.keycloak.authentication.authenticators.browser.WebAuthnPasswordlessAuthenticator;
import org.keycloak.common.util.Base64Url;
import org.keycloak.credential.CredentialModel;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.model.WebAuthnAuthenticatorsBean;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.services.messages.Messages;

/**
 * {@code portcullis-passkey} (contract §8.1): the stock passwordless WebAuthn
 * login, accepting the three passkey types ({@code webauthn-passwordless},
 * {@code portcullis-device-passkey}, {@code portcullis-security-key}). The
 * posted credential's type is found among the person's credentials before
 * Keycloak verifies it (through that type's credential provider); on success
 * the kind used, its method id, goes into the authentication note
 * {@link #KIND_NOTE}.
 *
 * <ul>
 * <li>Only kinds that are switched on are accepted; none on = it steps aside
 * ({@code attempted}).</li>
 * <li>{@code pc_method} ({@link PcMethod}) naming a passkey kind offers and
 * accepts only that kind's credentials ({@code passkey}: any kind); naming
 * another method, it steps aside.</li>
 * <li>When the person is already known (a step-up: {@code auth-cookie} set
 * them), the WebAuthn request lists exactly their credentials of the
 * accepted kinds ({@code allowCredentials}); none = it steps aside.</li>
 * </ul>
 */
public class PasskeyAuthenticator extends WebAuthnPasswordlessAuthenticator {
    /** The authentication note holding the kind (method id) that signed in. */
    public static final String KIND_NOTE = "portcullis.passkey.kind";

    private final Supplier<SigninConfig> config;

    /** The credential type of the passkey being offered or checked (this request only). */
    private String type;

    public PasskeyAuthenticator(KeycloakSession session, Supplier<SigninConfig> config) {
        super(session);
        this.config = config;
    }

    /** The kinds this authentication may use: switched on and allowed by {@code pc_method}. */
    List<String> acceptedKinds(AuthenticationFlowContext context) {
        SigninConfig cfg = config.get();
        Optional<String> requested = PcMethod.requested(context);
        List<String> out = new ArrayList<>(3);
        for (String k : Methods.PASSKEY_KINDS) {
            if (cfg.on(k) && PcMethod.allows(requested, k)) {
                out.add(k);
            }
        }
        return out;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        List<String> kinds = acceptedKinds(context);
        if (kinds.isEmpty()) {
            context.attempted();
            return;
        }
        UserModel user = context.getUser();
        if (user == null) {
            super.authenticate(context); // discoverable: the browser offers any passkey; action() checks its kind
            return;
        }
        List<String> held = new ArrayList<>(kinds.size());
        for (String k : kinds) {
            if (user.credentialManager().getStoredCredentialsByTypeStream(PasskeyClassifier.typeOf(k)).findAny().isPresent()) {
                held.add(k);
            }
        }
        if (held.isEmpty()) {
            context.attempted();
            return;
        }
        type = PasskeyClassifier.typeOf(held.get(0));
        try {
            LoginFormsProvider form = fillContextForm(context);
            if (form == null) {
                context.attempted();
                return;
            }
            if (held.size() > 1) {
                WebAuthnMetadataService metadata = getCredentialProvider(context.getSession()).getMetadataService();
                form.setAttribute(WebAuthnConstants.ALLOWED_AUTHENTICATORS,
                        new Allowed(context.getSession(), context.getRealm(), user, held, metadata));
            }
            context.challenge(form.createLoginWebAuthn());
        } finally {
            type = null;
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String posted = form.getFirst(WebAuthnConstants.CREDENTIAL_ID);
        if (posted == null || posted.isBlank() || form.containsKey("cancel")) {
            super.action(context); // the stock cancel / error / empty-form handling; nothing is verified
            return;
        }
        List<String> kinds = acceptedKinds(context);
        if (kinds.isEmpty()) {
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
            return;
        }
        UserModel user = owner(context, form.getFirst(WebAuthnConstants.USER_HANDLE));
        if (user == null) {
            super.action(context); // the stock "user not found" answer
            return;
        }
        byte[] credentialId;
        try {
            credentialId = Base64Url.decode(posted);
        } catch (RuntimeException e) {
            setErrorResponse(context, Messages.WEBAUTHN_ERROR_API_GET, "credential id unreadable");
            return;
        }
        Optional<String> kind = kindOf(user, credentialId, kinds);
        if (kind.isEmpty()) {
            // Not one of the person's passkeys of an accepted kind (another
            // kind than pc_method asks for, a switched-off kind, unknown).
            setErrorResponse(context, Messages.WEBAUTHN_ERROR_AUTH_VERIFICATION, "passkey kind not accepted");
            return;
        }
        type = PasskeyClassifier.typeOf(kind.get());
        try {
            super.action(context);
        } finally {
            type = null;
        }
        if (context.getStatus() == FlowStatus.SUCCESS) {
            context.getAuthenticationSession().setAuthNote(KIND_NOTE, kind.get());
        }
    }

    /** The person the posted passkey claims (its user handle), else the one already known. */
    private UserModel owner(AuthenticationFlowContext context, String userHandle) {
        String id;
        if (userHandle != null && !userHandle.isBlank()) {
            try {
                id = new String(Base64Url.decode(userHandle), StandardCharsets.UTF_8);
            } catch (RuntimeException e) {
                return null;
            }
        } else if (context.getUser() != null) {
            id = context.getUser().getId();
        } else {
            return null;
        }
        return session.users().getUserById(context.getRealm(), id);
    }

    /** The kind of the person's stored passkey with this credential id, among the accepted kinds. */
    static Optional<String> kindOf(UserModel user, byte[] credentialId, List<String> kinds) {
        for (String k : kinds) {
            boolean found = user.credentialManager().getStoredCredentialsByTypeStream(PasskeyClassifier.typeOf(k))
                    .anyMatch(c -> sameCredential(c, credentialId));
            if (found) {
                return Optional.of(k);
            }
        }
        return Optional.empty();
    }

    private static boolean sameCredential(CredentialModel c, byte[] credentialId) {
        try {
            String id = WebAuthnCredentialModel.createFromCredentialModel(c).getWebAuthnCredentialData().getCredentialId();
            return id != null && Arrays.equals(Base64.getDecoder().decode(id), credentialId);
        } catch (RuntimeException e) {
            return false;
        }
    }

    @Override
    protected String getCredentialType() {
        String t = type;
        return t == null ? super.getCredentialType() : t;
    }

    /** The person's credentials of several types, in the kinds' order (the form's {@code authenticators}). */
    static final class Allowed extends WebAuthnAuthenticatorsBean {
        private final List<WebAuthnAuthenticatorBean> all;

        Allowed(KeycloakSession session, RealmModel realm, UserModel user, List<String> kinds, WebAuthnMetadataService metadata) {
            super(session, realm, user, PasskeyClassifier.typeOf(kinds.get(0)), metadata);
            List<WebAuthnAuthenticatorBean> out = new ArrayList<>(super.getAuthenticators());
            for (String k : kinds.subList(1, kinds.size())) {
                out.addAll(new WebAuthnAuthenticatorsBean(session, realm, user, PasskeyClassifier.typeOf(k), metadata).getAuthenticators());
            }
            this.all = List.copyOf(out);
        }

        @Override
        public List<WebAuthnAuthenticatorBean> getAuthenticators() {
            return all;
        }
    }
}
