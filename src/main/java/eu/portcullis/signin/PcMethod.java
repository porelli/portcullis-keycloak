package eu.portcullis.signin;

import java.util.Optional;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * The one method a sign-in asks for (contract §8.1 "Step-up asks for one
 * method"). group-gate's step-up URL carries {@code pc_method=<method id or
 * "passkey">}; Keycloak keeps that unknown authorize parameter as the client
 * note {@code client_request_param_pc_method}. {@code portcullis-template}
 * asks for a missing method the same way, through the authentication note
 * {@link #STEP_NOTE} (it wins over the client note: it is the newer ask).
 * Only the six method ids and {@code passkey} are read; anything else is
 * ignored.
 */
public final class PcMethod {
    private PcMethod() {}

    /** The client note Keycloak keeps the authorize parameter in. */
    public static final String CLIENT_NOTE = "client_request_param_pc_method";

    /** The authentication note {@code portcullis-template} asks with. */
    public static final String STEP_NOTE = "portcullis.pc_method";

    /** Any passkey kind. */
    public static final String PASSKEY = "passkey";

    /** The method the authentication asks for, if any (six ids or {@code passkey}). */
    public static Optional<String> requested(AuthenticationFlowContext context) {
        AuthenticationSessionModel a = context == null ? null : context.getAuthenticationSession();
        if (a == null) {
            return Optional.empty();
        }
        Optional<String> step = parse(a.getAuthNote(STEP_NOTE));
        return step.isPresent() ? step : parse(a.getClientNote(CLIENT_NOTE));
    }

    /** v when it is one of the six method ids or {@code passkey}, exactly; else empty. */
    static Optional<String> parse(String v) {
        if (v == null) {
            return Optional.empty();
        }
        return PASSKEY.equals(v) || Methods.known(v) ? Optional.of(v) : Optional.empty();
    }

    /** Whether a request (empty = none) leaves method m to be used. */
    static boolean allows(Optional<String> requested, String m) {
        if (requested.isEmpty()) {
            return true;
        }
        String r = requested.get();
        return r.equals(m) || (PASSKEY.equals(r) && Methods.PASSKEY_KINDS.contains(m));
    }

    /** Whether methods meet the request (a passkey kind for {@code passkey}). */
    static boolean metBy(String requested, java.util.Set<String> methods) {
        if (PASSKEY.equals(requested)) {
            return Methods.PASSKEY_KINDS.stream().anyMatch(methods::contains);
        }
        return methods.contains(requested);
    }
}
