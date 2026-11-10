package eu.portcullis.signin;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Locale;
import java.util.Set;
import java.util.function.Supplier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.validation.Validation;

/**
 * {@code portcullis-password-form} (contract §8.1 "Passwords"): the stock
 * username and password form (the LDAP bind checks the password), without
 * its conditional passkey UI (passkeys sign in only through
 * {@code portcullis-passkey}, which knows their kinds).
 *
 * <ul>
 * <li>It steps aside ({@code attempted}) while {@code password} is off, or
 * when {@code pc_method} asks for another method; a form posted meanwhile
 * fails.</li>
 * <li>It always refuses {@link #NO_PASSWORD} (compared lowercased, by the
 * name typed and by the account it finds, so an e-mail address doesn't get
 * around it), before any password is checked, with "Password sign-in isn't
 * available for this account": the form shown again ({@code forceChallenge}),
 * which brute-force protection doesn't count — no password was checked, and
 * counting would let anyone lock these accounts out of every method. The
 * timing stays a wrong password's (a dummy hash).</li>
 * </ul>
 */
public class PasswordForm extends UsernamePasswordForm {
    /** Accounts that never sign in with a password (the bootstrap admin, the Hub's service account). */
    public static final Set<String> NO_PASSWORD = Set.of("admin", "portcullis-hub");

    /** Message key of the refusal (the jar's {@code theme-resources/messages}). */
    static final String REFUSED = "portcullisPasswordNotAvailable";

    static final String PASSWORD = "password";

    private final Supplier<SigninConfig> config;

    public PasswordForm(Supplier<SigninConfig> config) {
        super(); // no conditional passkey UI
        this.config = config;
    }

    /** Whether name is one of {@link #NO_PASSWORD} (trimmed, lowercased). */
    static boolean refused(String name) {
        return name != null && NO_PASSWORD.contains(name.trim().toLowerCase(Locale.ROOT));
    }

    private boolean usable(AuthenticationFlowContext context) {
        return config.get().on(PASSWORD) && PcMethod.allows(PcMethod.requested(context), PASSWORD);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel known = context.getUser();
        if (!usable(context) || (known != null && refused(known.getUsername()))) {
            context.attempted();
            return;
        }
        Offer.usableOnly(context, config.get());
        super.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        if (!form.containsKey("cancel") && !usable(context)) {
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
            return;
        }
        super.action(context);
    }

    @Override
    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> form) {
        boolean userSet = isUserAlreadySetBeforeUsernamePasswordAuth(context);
        String typed = form.getFirst(AuthenticationManager.FORM_USERNAME);
        UserModel target = userSet ? context.getUser() : lookup(context, typed);
        if ((!userSet && refused(typed)) || (target != null && refused(target.getUsername()))) {
            refuse(context, userSet, typed, target);
            return false;
        }
        return super.validateForm(context, form);
    }

    private static UserModel lookup(AuthenticationFlowContext context, String typed) {
        if (typed == null || typed.isBlank()) {
            return null;
        }
        String name = typed.trim();
        if (AuthenticatorUtils.isUsernameTooLong(name)) {
            return null;
        }
        try {
            return KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), name);
        } catch (ModelDuplicateException e) {
            return null; // the stock path answers it
        }
    }

    /** The refusal: the form again, not counted; the password is never checked. */
    private void refuse(AuthenticationFlowContext context, boolean userSet, String typed, UserModel target) {
        if (!userSet && typed != null) {
            String name = typed.trim();
            context.getEvent().detail(Details.USERNAME, name);
            context.getAuthenticationSession().setAuthNote(ATTEMPTED_USERNAME, name);
        }
        if (target != null) {
            context.getEvent().user(target);
        }
        AuthenticatorUtils.dummyHash(context);
        context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
        Response page = challenge(context, REFUSED, Validation.FIELD_PASSWORD);
        context.forceChallenge(page);
        if (!userSet) {
            context.clearUser();
        }
    }
}
