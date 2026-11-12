package eu.portcullis.signin;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

/**
 * {@code portcullis-x509} (contract §8.1 "Flows", §8 "The {@code mtls} amr
 * invariant"): Keycloak's X.509 client certificate authenticator (its own
 * trust, validity, revocation and user mapping checks), one execution per
 * certificate kind. Each execution's config names its method
 * ({@link #METHOD_CONFIG}: {@code yubikey_cert} with the reference value
 * {@code mtls}, {@code browser_cert} with {@code file}) and its CA file
 * ({@link #CA_CONFIG}: {@code pki_int}'s or {@code pki_file}'s certificate).
 *
 * <p>An execution steps aside ({@code attempted}) unless all of these hold:
 * its method is one of the two and switched on; {@code pc_method} allows it;
 * a certificate is presented; its CA file reads ({@link CaFile}: missing,
 * unreadable or not a CA = an ERROR naming portcullis); and the leaf was
 * issued by that CA ({@link #issuedBy}: issuer name and signature). So a
 * browser certificate never counts as {@code yubikey_cert} (never amr
 * {@code mtls}), and a YubiKey certificate never as {@code browser_cert}.
 * The CA file is read only when a leaf is presented and the method is on.
 * When it signs the person in it puts its own method in the authentication
 * note {@link #METHOD_NOTE}; before Keycloak's checks it adds the history
 * details {@code pc_method} / {@code pc_ua} ({@link History#onFailure}).
 *
 * <p>A certificate never signs in another person than the one already known
 * in this authentication (a step-up, a {@code portcullis-template} step):
 * the user is compared by id after the stock code ran, and on a difference
 * cleared and the sign-in failed ({@code USER_CONFLICT}). Keycloak's
 * processor refuses the switch too, but the stock authenticator turns that
 * refusal into {@code attempted}.
 */
public class X509Authenticator extends X509ClientCertificateAuthenticator {
    private static final Logger LOG = Logger.getLogger(X509Authenticator.class);

    /** The authentication note naming the certificate method that signed in. */
    public static final String METHOD_NOTE = "portcullis.x509.method";
    /** The execution config's method: {@code yubikey_cert} or {@code browser_cert}. */
    public static final String METHOD_CONFIG = "portcullis.method";
    /** The execution config's CA file (the PEM certificate of the CA whose leaves it counts). */
    public static final String CA_CONFIG = "portcullis.ca";

    static final String YUBIKEY_CERT = "yubikey_cert";
    static final String BROWSER_CERT = "browser_cert";

    private final Supplier<SigninConfig> config;
    private final Function<String, Optional<X509Certificate>> caFile;

    public X509Authenticator(boolean legacyCriticalBehavior, Supplier<SigninConfig> config) {
        this(legacyCriticalBehavior, config, CaFile::load);
    }

    X509Authenticator(boolean legacyCriticalBehavior, Supplier<SigninConfig> config,
            Function<String, Optional<X509Certificate>> caFile) {
        super(legacyCriticalBehavior);
        this.config = config;
        this.caFile = caFile;
    }

    /**
     * The method an execution config counts: {@code yubikey_cert} or
     * {@code browser_cert}; anything else (missing, another id) is null and
     * the execution steps aside.
     */
    static String method(AuthenticatorConfigModel cfg) {
        Map<String, String> c = cfg == null ? null : cfg.getConfig();
        String m = c == null ? null : c.get(METHOD_CONFIG);
        return YUBIKEY_CERT.equals(m) || BROWSER_CERT.equals(m) ? m : null;
    }

    /**
     * Whether ca issued leaf: the leaf's issuer is the CA's subject and its
     * signature verifies with the CA's key (the JDK's checks only).
     */
    static boolean issuedBy(X509Certificate leaf, X509Certificate ca) {
        if (leaf == null || ca == null) {
            return false;
        }
        try {
            if (!leaf.getIssuerX500Principal().equals(ca.getSubjectX500Principal())) {
                return false;
            }
            leaf.verify(ca.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** The method of this execution when it may run now (on, allowed by pc_method), else null. */
    private String usableMethod(AuthenticationFlowContext context) {
        String m = method(context.getAuthenticatorConfig());
        if (m == null || !config.get().on(m) || !PcMethod.allows(PcMethod.requested(context), m)) {
            return null;
        }
        return m;
    }

    /** The presented leaf (null: none or unreadable). */
    private X509Certificate leaf(AuthenticationFlowContext context) {
        try {
            X509Certificate[] chain = getCertificateChain(context);
            return chain == null || chain.length == 0 ? null : chain[0];
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Whether the leaf was issued by the CA of model's {@link #CA_CONFIG};
     * an unreadable CA file logs an ERROR and counts nothing.
     */
    private boolean ownLeaf(AuthenticatorConfigModel model, String method, X509Certificate leaf) {
        Map<String, String> c = model == null ? null : model.getConfig();
        String path = c == null ? null : c.get(CA_CONFIG);
        Optional<X509Certificate> ca;
        try {
            ca = caFile.apply(path);
        } catch (RuntimeException e) {
            ca = Optional.empty();
        }
        if (ca.isEmpty()) {
            LOG.errorf("portcullis: portcullis-x509 (%s): its CA file %s is missing, unreadable or not a CA certificate; no %s counts",
                    method, path, method);
            return false;
        }
        if (!issuedBy(leaf, ca.get())) {
            LOG.debugf("portcullis: portcullis-x509 (%s): the presented certificate wasn't issued by its CA", method);
            return false;
        }
        return true;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String m = usableMethod(context);
        if (m == null) {
            context.attempted();
            return;
        }
        X509Certificate leaf = leaf(context);
        if (leaf == null) {
            context.attempted(); // no certificate: the CA file is never read
            return;
        }
        if (!ownLeaf(context.getAuthenticatorConfig(), m, leaf)) {
            context.attempted();
            return;
        }
        History.onFailure(context, m);
        UserModel known = context.getUser();
        super.authenticate(context);
        if (sameUser(context, known)) {
            noteSuccess(context, m);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String m = usableMethod(context);
        if (m == null) {
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
            return;
        }
        MultivaluedMap<String, String> form = context.getHttpRequest() == null ? null
                : context.getHttpRequest().getDecodedFormParameters();
        if (form == null || !form.containsKey("cancel")) {
            // The confirmation counts only with this execution's own leaf presented.
            X509Certificate leaf = leaf(context);
            if (leaf == null || !ownLeaf(context.getAuthenticatorConfig(), m, leaf)) {
                context.failure(AuthenticationFlowError.ACCESS_DENIED);
                return;
            }
            History.onFailure(context, m);
        }
        UserModel known = context.getUser();
        super.action(context);
        if (sameUser(context, known)) {
            noteSuccess(context, m);
        }
    }

    /** False (and the sign-in failed, the user cleared) when the certificate's user isn't the one known before. */
    private static boolean sameUser(AuthenticationFlowContext context, UserModel known) {
        UserModel now = context.getUser();
        if (known == null || (now != null && known.getId().equals(now.getId()))) {
            return true;
        }
        LOG.infof("portcullis: a certificate of another account was presented while %s was signing in", known.getUsername());
        context.clearUser();
        context.getEvent().error(Errors.DIFFERENT_USER_AUTHENTICATED);
        Response page = context.form().setError(Messages.WEBAUTHN_ERROR_DIFFERENT_USER)
                .createErrorPage(Response.Status.UNAUTHORIZED);
        context.failure(AuthenticationFlowError.USER_CONFLICT, page);
        return false;
    }

    private static void noteSuccess(AuthenticationFlowContext context, String method) {
        if (context.getStatus() == FlowStatus.SUCCESS) {
            context.getAuthenticationSession().setAuthNote(METHOD_NOTE, method);
        }
    }

    /**
     * Whether this request presents a leaf issued by the CA of model's
     * {@link #CA_CONFIG} ({@link Offer}: an X.509 "Try another way" row
     * only then). No leaf: false, and the CA file isn't read.
     */
    boolean presentsOwnLeaf(AuthenticationFlowContext context, AuthenticatorConfigModel model) {
        String m = method(model);
        if (m == null) {
            return false;
        }
        X509Certificate leaf = leaf(context);
        return leaf != null && ownLeaf(model, m, leaf);
    }

    /**
     * The account the certificate this request presents maps to, with the
     * given execution's X.509 config (Keycloak's identity extractor and user
     * mapper), only when the leaf was issued by that execution's CA; empty
     * when there is none, it isn't that CA's, or it maps to nobody. The
     * trust and revocation checks run when the authenticator itself signs it
     * in.
     */
    Optional<UserModel> certificateUser(AuthenticationFlowContext context, AuthenticatorConfigModel model) {
        try {
            String m = method(model);
            if (m == null) {
                return Optional.empty();
            }
            X509Certificate[] chain = getCertificateChain(context);
            if (chain == null || chain.length == 0 || !ownLeaf(model, m, chain[0])) {
                return Optional.empty();
            }
            X509AuthenticatorConfigModel config = new X509AuthenticatorConfigModel(model);
            Object identity = getUserIdentityExtractor(config).extractUserIdentity(chain);
            return identity == null ? Optional.empty()
                    : Optional.ofNullable(getUserIdentityToModelMapper(config).find(context, identity));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
