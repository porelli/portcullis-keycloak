package eu.portcullis.signin;

import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import eu.portcullis.signin.store.PasskeyStore;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegister;
import org.keycloak.credential.CredentialModel;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.protocol.oidc.utils.AmrUtils;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * {@code webauthn-register-passwordless} (contract §8.1, plan D5 / D14): the
 * stock passwordless registration, plus
 *
 * <ul>
 * <li>{@code none} attestation accepted whatever the conveyance preference
 * (it counts as synced) and a {@link NullCertPathTrustworthinessVerifier}
 * (the realm truststore would reject FIDO chains; the kind comes from the
 * Hub's trust list instead);</li>
 * <li>the new passkey's kind ({@link PasskeyClassifier}), the credential
 * created through that kind's provider and type, and its attestation row
 * ({@link PasskeyStore}) in the same transaction;</li>
 * <li>the add-stronger cap ({@link #cap});</li>
 * <li>the form attribute {@code portcullisHints} ({@link #hintsFor});</li>
 * <li>a WARN when the realm's passwordless policy doesn't ask for
 * {@code direct} attestation ({@link #policyWarning}, once per change) and
 * on each registration without attestation ({@link #noAttestation}): with
 * any other conveyance the browser zeroes the AAGUID and sends none, so
 * every new passkey counts as synced;</li>
 * <li>never in an impersonated session ({@link ImpersonationGuard#impersonated},
 * D42): the challenge and the posted registration both answer
 * {@code portcullis-impersonating.ftl} (mode refused), nothing is stored
 * and the action is never completed.</li>
 * </ul>
 */
public class PasskeyRegister extends WebAuthnPasswordlessRegister {
    private static final Logger LOG = Logger.getLogger(PasskeyRegister.class);

    /** The form attribute core's {@code webauthnRegister.js} reads (a JSON array string). */
    public static final String HINTS_ATTRIBUTE = "portcullisHints";
    static final String ADMIN_GROUP = "lldap_admin";
    static final String HINTS_ADMIN = "[\"security-key\",\"client-device\",\"hybrid\"]";
    static final String HINTS_OTHERS = "[\"client-device\",\"hybrid\",\"security-key\"]";

    /** The amr of a setup-link session (contract §8 "Invite links"). */
    static final String SETUP_LINK_AMR = "inv";

    /** Message keys (the jar's {@code theme-resources/messages/messages_en.properties}). */
    static final String REFUSED_STRONGER = "portcullisPasskeyStrongerThanSession";
    static final String REFUSED_UNREADABLE = "portcullisPasskeyAttestationUnreadable";

    /** The conveyance core's policy asks for ({@code KC_REALM_SIGNIN_SETTINGS}). */
    static final String WANTED_CONVEYANCE = "direct";
    private static final Set<String> CONVEYANCES = Set.of("none", "indirect", "direct", "enterprise", "not specified");
    private static final UUID ZERO_AAGUID = new UUID(0L, 0L);
    /** Realm id → the conveyance last warned about (a drift is logged once per change). */
    private static final Map<String, String> POLICY_WARNED = new ConcurrentHashMap<>();

    private static final List<String> KINDS_STRONGEST_FIRST =
            List.of(PasskeyClassifier.SECURITY_KEY, PasskeyClassifier.DEVICE, PasskeyClassifier.SYNCED);

    private final KeycloakSession session;
    /** The identity cookie's session (Keycloak's; a test gives its own). */
    private final java.util.function.BiFunction<KeycloakSession, RealmModel, org.keycloak.services.managers.AuthenticationManager.AuthResult> identity;
    private final java.util.function.Function<String, String> env;

    /** The registration being processed (this provider lives for one request). */
    private Pending pending;

    private record Pending(StoredAttestation attestation, byte[] credentialId, String kind, String cappedAt) {}

    /** Whether a kind may be registered, and the cap it is stored with (null = none). */
    record Cap(boolean allowed, String cappedAt) {}

    public PasskeyRegister(KeycloakSession session) {
        this(session, (s, r) -> org.keycloak.services.managers.AuthenticationManager.authenticateIdentityCookie(s, r, true), System::getenv);
    }

    PasskeyRegister(KeycloakSession session,
            java.util.function.BiFunction<KeycloakSession, RealmModel, org.keycloak.services.managers.AuthenticationManager.AuthResult> identity,
            java.util.function.Function<String, String> env) {
        super(session, new NullCertPathTrustworthinessVerifier());
        this.session = session;
        this.identity = identity;
        this.env = env;
    }

    /**
     * In an impersonated session: the refusal page (a challenge; nothing
     * stored, the action never completed), and true.
     */
    private boolean refusedImpersonated(RequiredActionContext context) {
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        Optional<Impersonation.Info> imp = ImpersonationGuard.impersonated(context.getSession(), context.getRealm(), auth, identity);
        if (imp.isEmpty()) {
            return false;
        }
        UserModel user = context.getUser();
        String person = user == null ? null : user.getUsername();
        LOG.infof("portcullis: impersonation %s: passkey registration refused", imp.get().id());
        context.getEvent()
                .event(EventType.UPDATE_CREDENTIAL)
                .detail(WebAuthnConstants.REG_ERR_LABEL, "impersonated")
                .error(Errors.INVALID_REGISTRATION);
        String stop = Impersonation.stopUrl(env);
        org.keycloak.forms.login.LoginFormsProvider forms = context.form();
        ImpersonationBanner banner = ImpersonationBanner.of(imp.get(), person, stop, Instant.now());
        if (banner != null) {
            forms.setAttribute(ImpersonationResource.BANNER, banner);
        }
        context.challenge(forms.setAttribute(ImpersonationResource.ATTRIBUTE, ImpersonatingPage.refused(person, stop))
                .setStatus(Response.Status.FORBIDDEN).createForm(ImpersonationResource.PAGE));
        return true;
    }

    // ── The rules (pure; tested on their own) ──

    /**
     * The add-stronger cap (contract §8.1 "Adding a stronger method"). With
     * {@code add_stronger} on, or in a setup-link session ({@code inv}), any
     * kind is allowed without a cap. Otherwise the cap is the strongest kind
     * no stronger than the session's strongest switched-on method; a kind
     * above it (or any kind when nothing passkey-strong signed in, e.g. a
     * password alone) is refused.
     */
    static Cap cap(Set<String> sessionAmr, String kind, boolean addStronger, SigninConfig cfg) {
        if (PasskeyClassifier.rank(kind) < 0) {
            return new Cap(false, null);
        }
        if (addStronger || (sessionAmr != null && sessionAmr.contains(SETUP_LINK_AMR))) {
            return new Cap(true, null);
        }
        int best = 0;
        if (sessionAmr != null && cfg != null) {
            for (String amr : sessionAmr) {
                Optional<String> m = Methods.forAmr(amr).filter(cfg::on);
                if (m.isPresent()) {
                    best = Math.max(best, Methods.tenths(m.get()));
                }
            }
        }
        for (String k : KINDS_STRONGEST_FIRST) {
            if (Methods.tenths(k) <= best) {
                return PasskeyClassifier.rank(kind) <= PasskeyClassifier.rank(k) ? new Cap(true, k) : new Cap(false, null);
            }
        }
        return new Cap(false, null);
    }

    /**
     * The WARN for a realm whose passwordless policy asks for another
     * attestation conveyance than {@code direct}, or empty: once per realm
     * and value (logged again only after the value changed; back to direct
     * forgets it). Only the setting itself is named, an unknown value never
     * verbatim.
     */
    static Optional<String> policyWarning(String realmId, String conveyance) {
        String key = realmId == null ? "" : realmId;
        String c = conveyance == null || conveyance.isBlank() ? "not specified"
                : CONVEYANCES.contains(conveyance) ? conveyance : "an unrecognized value";
        if (WANTED_CONVEYANCE.equals(c)) {
            POLICY_WARNED.remove(key);
            return Optional.empty();
        }
        if (c.equals(POLICY_WARNED.put(key, c))) {
            return Optional.empty();
        }
        return Optional.of("portcullis: the realm's passkey policy asks for attestation " + c
                + ", not direct: passkeys can't be identified and count as synced; run ./portcullis keycloak configure");
    }

    /** Whether a registration carries no attestation: format {@code none} and an all-zero AAGUID. */
    static boolean noAttestation(StoredAttestation a) {
        return a != null && "none".equals(a.fmt()) && ZERO_AAGUID.equals(a.aaguid());
    }

    private static void warnIfPolicyDrifted(RealmModel realm) {
        try {
            WebAuthnPolicy policy = realm.getWebAuthnPolicyPasswordless();
            policyWarning(realm.getId(), policy == null ? null : policy.getAttestationConveyancePreference())
                    .ifPresent(LOG::warn);
        } catch (RuntimeException e) {
            LOG.debug("portcullis: the realm's passkey policy not read for the drift check");
        }
    }

    /** {@code portcullisHints}: the security key first for {@code lldap_admin} members. */
    static String hintsFor(UserModel user) {
        try {
            if (user != null && user.getGroupsStream().anyMatch(g -> ADMIN_GROUP.equals(g.getName()))) {
                return HINTS_ADMIN;
            }
        } catch (RuntimeException e) {
            LOG.debugf("portcullis: groups of %s not read for the registration hints", user.getUsername());
        }
        return HINTS_OTHERS;
    }

    /**
     * The session's raw amr values: the executions the user session completed
     * (within their max age) merged with those this authentication completed
     * so far, through Keycloak's own {@link AmrUtils}.
     */
    static Set<String> sessionAmr(RealmModel realm, AuthenticationSessionModel auth, UserSessionModel user) {
        Map<String, Integer> executions = new HashMap<>();
        if (user != null) {
            executions.putAll(AuthenticatorUtils.parseCompletedExecutions(user.getNote(Constants.AUTHENTICATORS_COMPLETED)));
        }
        if (auth != null) {
            executions.putAll(AuthenticatorUtils.parseCompletedExecutions(auth.getUserSessionNotes().get(Constants.AUTHENTICATORS_COMPLETED)));
        }
        if (executions.isEmpty()) {
            return Set.of();
        }
        return new LinkedHashSet<>(AmrUtils.getAuthenticationExecutionReferences(executions, realm));
    }

    // ── The required action ──

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        if (refusedImpersonated(context)) {
            return;
        }
        String action = context.getAuthenticationSession().getClientNote(Constants.KC_ACTION_PARAMETER);
        UserModel user = context.getUser();
        if (Constants.KC_ACTION_PARAMETER_SKIP_IF_EXISTS.equals(action) && hasPasskey(user)) {
            History.reapply(context); // the LOGIN may follow in this request
            context.success();
            return;
        }
        // LoginFormsProvider is one instance per session: the stock challenge
        // builds its form on the same provider, so the attribute reaches it.
        context.form().setAttribute(HINTS_ATTRIBUTE, hintsFor(user));
        super.requiredActionChallenge(context);
    }

    private static boolean hasPasskey(UserModel user) {
        for (String type : List.of(PasskeyClassifier.TYPE_SYNCED, PasskeyClassifier.TYPE_DEVICE, PasskeyClassifier.TYPE_SECURITY_KEY)) {
            if (user.credentialManager().getStoredCredentialsByTypeStream(type).findAny().isPresent()) {
                return true;
            }
        }
        return false;
    }

    /**
     * {@link #register}; on success, the sign-in's history details back on
     * {@code context.getEvent()}: the builder Keycloak sends this request's
     * {@code LOGIN} with when no other required action is left ({@link
     * History#reapply}).
     */
    @Override
    public void processAction(RequiredActionContext context) {
        if (refusedImpersonated(context)) {
            return;
        }
        register(context);
        if (context.getStatus() == RequiredActionContext.Status.SUCCESS) {
            History.reapply(context);
        }
    }

    void register(RequiredActionContext context) {
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        String retry = params.getFirst(WebAuthnConstants.IS_SET_RETRY);
        String browserError = params.getFirst(WebAuthnConstants.ERROR);
        String raw = params.getFirst(WebAuthnConstants.ATTESTATION_OBJECT);
        if ((retry != null && !retry.isEmpty()) || (browserError != null && !browserError.isEmpty()) || raw == null) {
            super.processAction(context); // the stock retry / error handling
            return;
        }

        warnIfPolicyDrifted(context.getRealm());
        StoredAttestation a;
        byte[] credentialId;
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(raw);
            a = PasskeyClassifier.parse(bytes);
            credentialId = PasskeyClassifier.credentialId(a);
        } catch (RuntimeException e) {
            refuse(context, REFUSED_UNREADABLE, "attestation_unreadable");
            return;
        }

        SigninConfig cfg = SigninConfig.current();
        String kind = PasskeyClassifier.kind(a, cfg, Instant.now());
        if (noAttestation(a)) {
            UserModel u = context.getUser();
            LOG.warnf("portcullis: passkey registration for %s: no attestation: classified %s", u == null ? "?" : u.getUsername(), kind);
        }
        RealmModel realm = context.getRealm();
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        UserSessionModel userSession = auth.getParentSession() == null ? null
                : session.sessions().getUserSession(realm, auth.getParentSession().getId());
        Cap cap = cap(sessionAmr(realm, auth, userSession), kind, cfg.addStronger(), cfg);
        UserModel user = context.getUser();
        if (!cap.allowed()) {
            LOG.infof("portcullis: passkey registration refused for %s: AAGUID %s is %s, stronger than the session", user.getUsername(), a.aaguid(), kind);
            refuse(context, REFUSED_STRONGER, "stronger_than_session");
            return;
        }

        pending = new Pending(a, credentialId, kind, cap.cappedAt());
        try {
            super.processAction(context);
            if (context.getStatus() != RequiredActionContext.Status.SUCCESS) {
                return;
            }
            String type = PasskeyClassifier.typeOf(kind);
            CredentialModel created = user.credentialManager().getStoredCredentialsByTypeStream(type)
                    .filter(c -> sameCredential(c, credentialId))
                    .findFirst()
                    // Fail closed: the transaction rolls back, nothing is kept.
                    .orElseThrow(() -> new IllegalStateException("portcullis: the new passkey credential wasn't found"));
            PasskeyStore.of(session).put(realm, user, created, a, kind, cap.cappedAt(), cfg.mdsSerial());
            LOG.infof("portcullis: passkey registered for %s: AAGUID %s, kind %s", user.getUsername(), a.aaguid(), kind);
        } finally {
            pending = null;
        }
    }

    private static boolean sameCredential(CredentialModel c, byte[] credentialId) {
        try {
            String id = WebAuthnCredentialModel.createFromCredentialModel(c).getWebAuthnCredentialData().getCredentialId();
            return id != null && Arrays.equals(Base64.getDecoder().decode(id), credentialId);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private void refuse(RequiredActionContext context, String message, String why) {
        context.getEvent()
                .event(EventType.UPDATE_CREDENTIAL)
                .detail(Details.CREDENTIAL_TYPE, getCredentialType())
                .detail(WebAuthnConstants.REG_ERR_LABEL, why)
                .error(Errors.INVALID_REGISTRATION);
        Response page = context.form()
                .setError(message)
                .setAttribute("webAuthnTitle", Messages.WEBAUTHN_REGISTER_TITLE)
                .createWebAuthnErrorPage();
        context.challenge(page);
    }

    @Override
    protected String getCredentialType() {
        Pending p = pending;
        return p == null ? super.getCredentialType() : PasskeyClassifier.typeOf(p.kind());
    }

    @Override
    protected String getCredentialProviderId() {
        Pending p = pending;
        return p == null ? super.getCredentialProviderId() : PasskeyCredentialProviders.providerIdOf(p.kind());
    }

    /**
     * The stock verifiers, with {@code none} attestation accepted whatever
     * the policy's conveyance preference (core asks for {@code direct}; a
     * synced passkey often answers {@code none}, which counts as synced).
     */
    @Override
    protected WebAuthnRegistrationManager createWebAuthnRegistrationManager(WebAuthnPolicy policy) {
        List<AttestationStatementVerifier> verifiers = new ArrayList<>(6);
        verifiers.add(new NoneAttestationStatementVerifier());
        verifiers.add(new PackedAttestationStatementVerifier());
        verifiers.add(new TPMAttestationStatementVerifier());
        verifiers.add(new AndroidKeyAttestationStatementVerifier());
        verifiers.add(new AndroidSafetyNetAttestationStatementVerifier());
        verifiers.add(new FIDOU2FAttestationStatementVerifier());
        DefaultSelfAttestationTrustworthinessVerifier self = new DefaultSelfAttestationTrustworthinessVerifier();
        List<String> acceptable = policy.getAcceptableAaguids();
        self.setSelfAttestationAllowed(acceptable == null || acceptable.isEmpty());
        return new WebAuthnRegistrationManager(verifiers, new NullCertPathTrustworthinessVerifier(), self,
                Collections.emptyList(), new ObjectConverter());
    }
}
