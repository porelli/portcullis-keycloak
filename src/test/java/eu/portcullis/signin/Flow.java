package eu.portcullis.signin;

import com.webauthn4j.converter.util.ObjectConverter;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Predicate;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.browser.WebAuthnMetadataService;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProvider;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * One authentication in progress, for the authenticators' tests: a realm
 * with the executions it completed (each with its reference value and a
 * 10 h max age, like core's flows), an authentication session's notes, the
 * login form's attributes, the people Keycloak knows, and what the
 * authenticator answered (status, error, form, reset).
 */
final class Flow {
    static final String REALM = "portcullis";
    static final URI BASE = URI.create("https://auth.example.com/");

    final Map<String, String> authNotes = new HashMap<>();
    final Map<String, String> clientNotes = new HashMap<>();
    final Map<String, String> userSessionNotes = new HashMap<>();
    final Map<String, Object> formAttributes = new LinkedHashMap<>();
    final MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();
    final Map<String, AuthenticationExecutionModel> executions = new HashMap<>();
    final Map<String, AuthenticatorConfigModel> configs = new HashMap<>();
    /** Flow id → its executions, in order (for code that walks the flow). */
    final Map<String, List<AuthenticationExecutionModel>> flows = new HashMap<>();
    /** The client certificate chain this request presents (null: none). */
    java.security.cert.X509Certificate[] certificates;
    /** Keycloak's processor refuses a second, different user (USER_CONFLICT); off = a lenient processor. */
    boolean strictUser;
    final Map<String, UserModel> users = new HashMap<>();
    final Map<String, UserModel> emails = new HashMap<>();
    final List<String> eventErrors = new ArrayList<>();
    /** The event's details at each error (a LOGIN_ERROR as Keycloak would send it). */
    final List<Map<String, String>> errorDetails = new ArrayList<>();
    /** The request's HTTP headers. */
    final Map<String, String> headers = new HashMap<>();
    final List<String> formErrors = new ArrayList<>();

    UserModel user;
    List<org.keycloak.authentication.AuthenticationSelectionOption> selections;
    FlowStatus status;
    AuthenticationFlowError error;
    String page;
    Runnable resetListener;
    UserSessionModel attached;
    AuthenticatorConfigModel authenticatorConfig;
    String clientId = "nextcloud";
    /** This request's URI (default: the authorize endpoint with its query). */
    URI requestUri = BASE.resolve("realms/portcullis/protocol/openid-connect/auth?client_id=nextcloud&state=s1");
    /** The authentication selections were cleared (no "Try another way"). */
    boolean selectionsCleared;
    boolean bruteForceProtected = true;

    /** The root authentication session's id (Keycloak: the user session's id, AuthenticationSessionManager.getUserSession). */
    String rootId = "root-1";
    /** The user sessions Keycloak knows, by id (session.sessions().getUserSession). */
    final Map<String, UserSessionModel> userSessions = new HashMap<>();

    final RealmModel realm;
    final KeycloakSession session;
    /** Keycloak's own OTP credential provider ({@code keycloak-otp}), over this session. */
    private final CredentialProvider<?>[] otpProvider = new CredentialProvider<?>[1];
    /** The stand-ins behind realm, session and the session's context: a test adds answers. */
    final Fake realmFake;
    final Fake sessionFake;
    final Fake contextFake;
    final AuthenticationSessionModel authSession;
    final LoginFormsProvider forms;
    final AuthenticationFlowContext context;
    final EventBuilder event;
    AuthenticationFlowModel top;

    Flow() {
        WebAuthnMetadataService.setDefaultMetadata(Map.of());
        realmFake = Fake.named("realm")
                .ret("getId", "realm-1")
                .ret("getName", REALM)
                .on("getAuthenticationExecutionById", a -> executions.get((String) a[0]))
                .on("getAuthenticatorConfigById", a -> configs.get((String) a[0]))
                .on("getAuthenticationExecutionsStream", a -> flows.getOrDefault((String) a[0], List.of()).stream())
                .on("isBruteForceProtected", a -> bruteForceProtected)
                .on("isLoginWithEmailAllowed", a -> !emails.isEmpty())
                .on("getWebAuthnPolicyPasswordless", a -> new WebAuthnPolicy())
                .on("getAuthenticationFlowsStream", a -> flows.keySet().stream().sorted().map(id -> {
                    AuthenticationFlowModel m = new AuthenticationFlowModel();
                    m.setId(id);
                    return m;
                }));
        realm = realmFake.as(RealmModel.class);
        ClientModel client = Fake.named("client").on("getClientId", a -> clientId).as(ClientModel.class);
        authSession = Fake.named("authSession")
                .on("getAuthNote", a -> authNotes.get((String) a[0]))
                .on("setAuthNote", a -> authNotes.put((String) a[0], (String) a[1]))
                .on("removeAuthNote", a -> authNotes.remove((String) a[0]))
                .on("getClientNote", a -> clientNotes.get((String) a[0]))
                .on("setClientNote", a -> clientNotes.put((String) a[0], (String) a[1]))
                .on("getClientNotes", a -> clientNotes)
                .on("getUserSessionNotes", a -> new HashMap<>(userSessionNotes))
                .on("setUserSessionNote", a -> userSessionNotes.put((String) a[0], (String) a[1]))
                .on("getAuthenticatedUser", a -> user)
                .on("setAuthenticatedUser", a -> user = (UserModel) a[0])
                .on("getClient", a -> client)
                .on("getRealm", a -> realm)
                .on("getParentSession", a -> Fake.named("root auth session").ret("getId", rootId)
                        .as(org.keycloak.sessions.RootAuthenticationSessionModel.class))
                .ret("getProtocol", "openid-connect")
                .as(AuthenticationSessionModel.class);
        UserProvider userProvider = Fake.named("users")
                .on("getUserByUsername", a -> users.get(((String) a[1]).toLowerCase(Locale.ROOT)))
                .on("getUserByEmail", a -> emails.get((String) a[1]))
                .on("getUserById", a -> users.values().stream().filter(u -> u.getId().equals(a[1])).findFirst().orElse(null))
                .as(UserProvider.class);
        contextFake = Fake.named("context")
                .ret("resolveLocale", Locale.ENGLISH)
                .on("getAuthenticationSession", a -> authSession)
                .on("getRealm", a -> realm);
        KeycloakContext keycloakContext = contextFake.as(KeycloakContext.class);
        org.keycloak.models.UserSessionProvider sessions = Fake.named("user sessions")
                .on("getUserSession", a -> userSessions.get((String) a[1]))
                .as(org.keycloak.models.UserSessionProvider.class);
        KeycloakSessionFactory factory = Fake.named("factory").as(KeycloakSessionFactory.class);
        PasswordHashProvider hash = Fake.named("hash").as(PasswordHashProvider.class);
        Map<Class<?>, Object> providers = new HashMap<>();
        providers.put(PasswordHashProvider.class, hash);
        providers.put(org.keycloak.services.x509.X509ClientCertificateLookup.class,
                Fake.named("x509 lookup").on("getCertificateChain", a -> certificates)
                        .as(org.keycloak.services.x509.X509ClientCertificateLookup.class));
        // No identity cookie: AuthenticationManager.authenticateIdentityCookie answers null (not signed in).
        providers.put(org.keycloak.cookie.CookieProvider.class, Fake.named("cookies").as(org.keycloak.cookie.CookieProvider.class));
        sessionFake = Fake.named("session")
                .ret("users", userProvider)
                .ret("sessions", sessions)
                .ret("getContext", keycloakContext)
                .ret("getKeycloakSessionFactory", factory)
                .ret("getAttributes", new HashMap<>())
                .on("getProvider", a -> a.length == 2 && "keycloak-otp".equals(a[1]) ? otpProvider[0] : providers.get((Class<?>) a[0]));
        session = sessionFake.as(KeycloakSession.class);
        otpProvider[0] = new org.keycloak.credential.OTPCredentialProvider(session);
        providers.put(CredentialProvider.class,
                new WebAuthnPasswordlessCredentialProvider(session, new WebAuthnMetadataService(), new ObjectConverter()));
        forms = Fake.named("forms")
                .fluent(LoginFormsProvider.class)
                .on("setAttribute", a -> {
                    formAttributes.put((String) a[0], a[1]);
                    return null;
                })
                .on("setError", a -> {
                    formErrors.add((String) a[0]);
                    return null;
                })
                .on("addError", a -> {
                    formErrors.add(((org.keycloak.models.utils.FormMessage) a[0]).getMessage());
                    return null;
                })
                .on("createForm", a -> {
                    page = (String) a[0];
                    return null;
                })
                .on("createLoginWebAuthn", a -> {
                    page = "webauthn-authenticate";
                    return null;
                })
                .on("createLoginTotp", a -> {
                    page = "login-otp";
                    return null;
                })
                .on("createLoginUsernamePassword", a -> {
                    page = "login";
                    return null;
                })
                .on("createErrorPage", a -> {
                    page = "error";
                    return null;
                })
                .on("createWebAuthnErrorPage", a -> {
                    page = "webauthn-error";
                    return null;
                })
                .as(LoginFormsProvider.class);
        // Fluent setters must return the provider: Fake answers null above, so wrap.
        LoginFormsProvider fluentForms = fluent(forms);
        providers.put(LoginFormsProvider.class, fluentForms);
        event = new EventBuilder(realm, session) {
            @Override
            public void error(String e) {
                eventErrors.add(e);
                Map<String, String> d = getEvent().getDetails();
                errorDetails.add(d == null ? Map.of() : new HashMap<>(d));
            }

            @Override
            public void success() {}
        };
        jakarta.ws.rs.core.HttpHeaders httpHeaders = Fake.named("headers")
                .on("getHeaderString", a -> headers.entrySet().stream().filter(h -> h.getKey().equalsIgnoreCase((String) a[0]))
                        .map(Map.Entry::getValue).findFirst().orElse(null))
                .as(jakarta.ws.rs.core.HttpHeaders.class);
        HttpRequest http = Fake.named("http").on("getDecodedFormParameters", a -> form)
                .ret("getHttpHeaders", httpHeaders).as(HttpRequest.class);
        UriInfo uri = Fake.named("uri").ret("getBaseUri", BASE).on("getRequestUri", a -> requestUri).as(UriInfo.class);
        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setId("exec-current");
        AuthenticationFlowModel top = new AuthenticationFlowModel();
        top.setId("flow-top");
        this.top = top;
        org.keycloak.services.managers.BruteForceProtector protector =
                Fake.named("brute force").as(org.keycloak.services.managers.BruteForceProtector.class);
        context = Fake.named("flow")
                .on("getProtector", a -> protector)
                .on("getAuthenticationSession", a -> authSession)
                .on("getRealm", a -> realm)
                .on("getSession", a -> session)
                .on("getUser", a -> user)
                .on("setUser", a -> {
                    UserModel u = (UserModel) a[0];
                    if (strictUser && user != null && !user.getId().equals(u.getId())) {
                        throw new org.keycloak.authentication.AuthenticationFlowException(AuthenticationFlowError.USER_CONFLICT);
                    }
                    user = u;
                    return null;
                })
                .on("clearUser", a -> user = null)
                .on("attachUserSession", a -> attached = (UserSessionModel) a[0])
                .on("getExecution", a -> execution)
                .on("getTopLevelFlow", a -> this.top)
                .on("getAuthenticatorConfig", a -> authenticatorConfig)
                .on("getHttpRequest", a -> http)
                .on("getUriInfo", a -> uri)
                .on("getEvent", a -> event)
                .on("form", a -> fluentForms)
                .on("success", a -> status = FlowStatus.SUCCESS)
                .on("attempted", a -> status = FlowStatus.ATTEMPTED)
                .on("failure", a -> {
                    status = FlowStatus.FAILED;
                    error = (AuthenticationFlowError) a[0];
                    return null;
                })
                .on("challenge", a -> status = FlowStatus.CHALLENGE)
                .on("forceChallenge", a -> status = FlowStatus.FORCE_CHALLENGE)
                .on("failureChallenge", a -> {
                    status = FlowStatus.FAILURE_CHALLENGE;
                    error = (AuthenticationFlowError) a[0];
                    return null;
                })
                .on("resetFlow", a -> {
                    status = FlowStatus.FLOW_RESET;
                    resetListener = a.length > 0 ? (Runnable) a[0] : null;
                    return null;
                })
                .on("getAuthenticationSelections", a -> selections)
                .on("setAuthenticationSelections", a -> {
                    @SuppressWarnings("unchecked")
                    List<org.keycloak.authentication.AuthenticationSelectionOption> l =
                            (List<org.keycloak.authentication.AuthenticationSelectionOption>) a[0];
                    selections = l;
                    selectionsCleared = l != null && l.isEmpty();
                    return null;
                })
                .on("getStatus", a -> status)
                .on("getError", a -> error)
                .as(AuthenticationFlowContext.class);
    }

    /** The event's details now (e.g. the LOGIN event's at the end of the flow). */
    Map<String, String> eventDetails() {
        Map<String, String> d = event.getEvent().getDetails();
        return d == null ? Map.of() : d;
    }

    /** Whether Keycloak's flow would count this answer as a brute-force failure (FAILED, FAILURE_CHALLENGE). */
    boolean countedByBruteForce() {
        return status == FlowStatus.FAILED || status == FlowStatus.FAILURE_CHALLENGE;
    }

    /** A LoginFormsProvider whose fluent setters return itself. */
    private static LoginFormsProvider fluent(LoginFormsProvider inner) {
        return (LoginFormsProvider) java.lang.reflect.Proxy.newProxyInstance(Flow.class.getClassLoader(),
                new Class<?>[] {LoginFormsProvider.class}, (p, m, args) -> {
                    Object r = m.invoke(inner, args);
                    return m.getReturnType() == LoginFormsProvider.class ? p : r;
                });
    }

    // ── People ──

    /** A person: their username, password and passkeys. */
    final class Person {
        final String id;
        final String username;
        String password;
        final Map<String, List<CredentialModel>> credentials = new HashMap<>();
        final List<CredentialInput> checked = new ArrayList<>();
        Predicate<CredentialInput> passkeyValid = i -> true;
        /** The authenticator-app codes that verify (none by default). */
        Predicate<CredentialInput> otpValid = i -> false;
        final UserModel model;
        /** The stand-in behind model: a test adds answers (groups, required actions, …). */
        final Fake fake;

        Person(String id, String username) {
            this.id = id;
            this.username = username;
            SubjectCredentialManager manager = Fake.named("credentials " + username)
                    .on("getStoredCredentialsByTypeStream", a -> credentials.getOrDefault((String) a[0], List.of()).stream())
                    .on("isConfiguredFor", a -> !credentials.getOrDefault((String) a[0], List.of()).isEmpty())
                    .on("getStoredCredentialById", a -> credentials.values().stream().flatMap(List::stream)
                            .filter(c -> c.getId().equals(a[0])).findFirst().orElse(null))
                    .on("removeStoredCredentialById", a -> credentials.values().stream()
                            .anyMatch(l -> l.removeIf(c -> c.getId().equals(a[0]))))
                    .on("isValid", a -> {
                        @SuppressWarnings("unchecked")
                        List<CredentialInput> in = a[0] instanceof List ? (List<CredentialInput>) a[0] : List.of((CredentialInput[]) a[0]);
                        for (CredentialInput i : in) {
                            checked.add(i);
                            boolean ok = "password".equals(i.getType())
                                    ? password != null && password.equals(i.getChallengeResponse())
                                    : "otp".equals(i.getType()) ? otpValid.test(i) : passkeyValid.test(i);
                            if (!ok) {
                                return false;
                            }
                        }
                        return true;
                    })
                    .as(SubjectCredentialManager.class);
            fake = Fake.named("user " + username)
                    .ret("getId", id)
                    .ret("getUsername", username)
                    .ret("isEnabled", true)
                    .ret("credentialManager", manager);
            model = fake.as(UserModel.class);
        }

        /** A stored authenticator app (credential type otp) with this id and label. */
        Person otp(String credentialId, String label) {
            CredentialModel c = new CredentialModel();
            c.setId(credentialId);
            c.setType("otp");
            c.setUserLabel(label);
            c.setCreatedDate(Time.currentTimeMillis());
            credentials.computeIfAbsent("otp", k -> new ArrayList<>()).add(c);
            return this;
        }

        /** A stored passkey of credential type t with this credential id. */
        Person passkey(String type, byte[] credentialId) {
            WebAuthnCredentialModel c = WebAuthnCredentialModel.create(type, "key", "00000000-0000-0000-0000-000000000000",
                    Base64.getEncoder().encodeToString(credentialId), null, null, 0, "none");
            c.setId(type + "-" + credentials.getOrDefault(type, List.of()).size());
            c.setCreatedDate(Time.currentTimeMillis());
            credentials.computeIfAbsent(type, k -> new ArrayList<>()).add(c);
            return this;
        }
    }

    private final List<Person> people = new ArrayList<>();

    Person person(String id, String username) {
        Person p = new Person(id, username);
        users.put(username, p.model);
        people.add(p);
        return p;
    }

    List<Person> people() {
        return people;
    }

    /** The form's error messages (general and per field). */
    List<String> formErrorsOrFieldErrors() {
        return formErrors;
    }

    // ── Completed executions (amr) ──

    /** An execution with reference value amr (max age 10 h); its id. */
    String execution(String amr) {
        String id = "exec-" + amr;
        AuthenticationExecutionModel e = new AuthenticationExecutionModel();
        e.setId(id);
        e.setAuthenticatorConfig("cfg-" + amr);
        executions.put(id, e);
        AuthenticatorConfigModel c = new AuthenticatorConfigModel();
        c.setId("cfg-" + amr);
        c.setConfig(new HashMap<>(Map.of(Constants.AUTHENTICATION_EXECUTION_REFERENCE_VALUE, amr,
                Constants.AUTHENTICATION_EXECUTION_REFERENCE_MAX_AGE, "36000")));
        configs.put(c.getId(), c);
        return id;
    }

    /** The completed-executions note for these amr values, completed now. */
    String completedNote(String... amrs) {
        StringBuilder b = new StringBuilder("{");
        for (int i = 0; i < amrs.length; i++) {
            b.append(i == 0 ? "" : ",").append('"').append(execution(amrs[i])).append("\":").append(Time.currentTimeSeconds());
        }
        return b.append('}').toString();
    }

    /** This authentication completed executions with these amr values. */
    Flow completed(String... amrs) {
        userSessionNotes.put(Constants.AUTHENTICATORS_COMPLETED, completedNote(amrs));
        return this;
    }

    /** An SSO user session of person p whose amr is amrs. */
    UserSessionModel userSession(Person p, String... amrs) {
        Map<String, String> notes = new HashMap<>();
        notes.put(Constants.AUTHENTICATORS_COMPLETED, completedNote(amrs));
        return Fake.named("user session")
                .ret("getId", "us-1")
                .ret("getUser", p.model)
                .ret("getRealm", realm)
                .on("getNote", a -> notes.get((String) a[0]))
                .on("setNote", a -> notes.put((String) a[0], (String) a[1]))
                .as(UserSessionModel.class);
    }

    /** The execution's config (Keycloak's authenticator config of this execution). */
    Flow config(Map<String, String> c) {
        AuthenticatorConfigModel m = new AuthenticatorConfigModel();
        m.setId("cfg-current");
        m.setConfig(new HashMap<>(c));
        authenticatorConfig = m;
        return this;
    }

    static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
