package eu.portcullis.signin;

import eu.portcullis.signin.store.PasskeyEntity;
import eu.portcullis.signin.store.PasskeyStore;
import jakarta.ws.rs.core.MultivaluedMap;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;
import org.jboss.logging.Logger;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
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
 * <li>A passkey whose model's trust-list entry is {@code revoked} signs in
 * as {@code passkey_synced}, whatever its stored kind, until reclassification
 * rewrites it (a missing or unreadable store row counts the same: fail
 * closed); that kind must then be accepted.</li>
 * </ul>
 *
 * <p>It is <b>not</b> a {@code CredentialValidator} (it wraps the stock
 * authenticator instead of extending it): Keycloak's
 * {@code AuthenticationSelectionResolver} runs, in place of the execution
 * being tried, the first of the flow's selectable executions, and lists
 * every non-credential execution before the credential ones that need no
 * user. As the stock passwordless authenticator, a credential validator, it
 * came after the password form and never ran; as a plain authenticator the
 * flow's own order (passkey sub-flow before the password form) decides. The
 * sign-in page's "Try another way" offers only methods that can be used
 * ({@link Offer}).
 */
public class PasskeyAuthenticator implements Authenticator {
    /** The authentication note holding the kind (method id) that signed in. */
    public static final String KIND_NOTE = "portcullis.passkey.kind";

    private static final Logger LOG = Logger.getLogger(PasskeyAuthenticator.class);
    private static final String SYNCED = "passkey_synced";

    private final Stock stock;
    private final Supplier<SigninConfig> config;

    public PasskeyAuthenticator(KeycloakSession session, Supplier<SigninConfig> config) {
        this(session, config, id -> PasskeyStore.of(session).get(id).map(PasskeyEntity::getAaguid));
    }

    /**
     * {@code aaguidOf}: a Keycloak credential id → the AAGUID of its passkey
     * store row (empty: no row).
     */
    PasskeyAuthenticator(KeycloakSession session, Supplier<SigninConfig> config, Function<String, Optional<String>> aaguidOf) {
        this.stock = new Stock(session, config, aaguidOf);
        this.config = config;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Offer.usableOnly(context, config.get());
        stock.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        stock.action(context);
    }

    List<String> acceptedKinds(AuthenticationFlowContext context) {
        return stock.acceptedKinds(context);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void close() {}

    /** The stock passwordless authenticator, with the kinds. */
    static final class Stock extends WebAuthnPasswordlessAuthenticator {
        private final Supplier<SigninConfig> config;
        private final Function<String, Optional<String>> aaguidOf;

        /** The credential type of the passkey being offered or checked (this request only). */
        private String type;

        Stock(KeycloakSession session, Supplier<SigninConfig> config, Function<String, Optional<String>> aaguidOf) {
            super(session);
            this.config = config;
            this.aaguidOf = aaguidOf;
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
            Optional<Held> held = heldOf(user, credentialId, Methods.PASSKEY_KINDS);
            if (held.isEmpty() || !kinds.contains(held.get().kind)) {
                // Not one of the person's passkeys of an accepted kind (another
                // kind than pc_method asks for, a switched-off kind, unknown).
                setErrorResponse(context, Messages.WEBAUTHN_ERROR_AUTH_VERIFICATION, "passkey kind not accepted");
                return;
            }
            // Its model revoked since it was stored (or no store row): it signs
            // in as synced until reclassification rewrites it — and only where
            // synced is accepted.
            String kind = signInKind(user, held.get(), config.get());
            if (!kinds.contains(kind)) {
                setErrorResponse(context, Messages.WEBAUTHN_ERROR_AUTH_VERIFICATION, "passkey kind not accepted");
                return;
            }
            type = PasskeyClassifier.typeOf(held.get().kind);
            try {
                super.action(context);
            } finally {
                type = null;
            }
            if (context.getStatus() == FlowStatus.SUCCESS) {
                context.getAuthenticationSession().setAuthNote(KIND_NOTE, kind);
            }
        }

        /**
         * The kind a stored passkey signs in as: its stored kind, capped at
         * {@code passkey_synced} when the trust list's entry for its model
         * (the store row's AAGUID) is {@code revoked}, or when that row can't
         * be read (fail closed: no proof of the stronger kind).
         */
        String signInKind(UserModel user, Held held, SigninConfig cfg) {
            if (SYNCED.equals(held.kind)) {
                return held.kind;
            }
            Optional<String> aaguid;
            try {
                aaguid = aaguidOf.apply(held.credential.getId());
            } catch (RuntimeException e) {
                LOG.warnf("portcullis: passkey of %s (%s) signs in as %s: its store row can't be read", user.getUsername(), held.kind, SYNCED);
                return SYNCED;
            }
            if (aaguid.isEmpty()) {
                LOG.warnf("portcullis: passkey of %s (%s) signs in as %s: no store row", user.getUsername(), held.kind, SYNCED);
                return SYNCED;
            }
            UUID id;
            try {
                id = UUID.fromString(aaguid.get());
            } catch (IllegalArgumentException e) {
                return SYNCED;
            }
            if (cfg.authenticator(id).map(t -> "revoked".equals(t.status())).orElse(false)) {
                LOG.infof("portcullis: passkey of %s (AAGUID %s, %s) signs in as %s: its model is revoked", user.getUsername(), id, held.kind, SYNCED);
                return SYNCED;
            }
            return held.kind;
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

        /** A person's stored passkey: its stored kind and Keycloak credential. */
        record Held(String kind, CredentialModel credential) {}

        /** The person's stored passkey with this credential id, among kinds. */
        static Optional<Held> heldOf(UserModel user, byte[] credentialId, List<String> kinds) {
            for (String k : kinds) {
                Optional<CredentialModel> found = user.credentialManager().getStoredCredentialsByTypeStream(PasskeyClassifier.typeOf(k))
                        .filter(c -> sameCredential(c, credentialId)).findFirst();
                if (found.isPresent()) {
                    return Optional.of(new Held(k, found.get()));
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
