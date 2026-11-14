package eu.portcullis.signin;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.models.Constants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.utils.AmrUtils;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * The sign-in method table (contract §8.1 "Methods", plan D1), the same in
 * the Hub ({@code internal/signin}), group-gate, mcp-gate and here.
 */
public final class Methods {
    private Methods() {}

    /** A method: its id, amr value and strength in tenths. */
    private record Info(String id, String amr, int tenths) {}

    /** Every method, in canonical order (weakest first). */
    private static final List<Info> TABLE = List.of(
            new Info("password", "pwd", 10),
            new Info("totp", "otp", 15),
            new Info("passkey_synced", "spk", 25),
            new Info("browser_cert", "file", 25),
            new Info("passkey_device", "dpk", 30),
            new Info("security_key", "hwk", 35),
            new Info("yubikey_cert", "mtls", 40));

    /** The seven method ids, in canonical order. */
    public static final List<String> IDS = TABLE.stream().map(Info::id).toList();

    /** Methods that can't be switched on yet: off whatever the file says (none since sign-in part 2). */
    static final Set<String> UNAVAILABLE = Set.of();

    /** The three passkey kinds, weakest first. */
    public static final List<String> PASSKEY_KINDS = List.of("passkey_synced", "passkey_device", "security_key");

    /** Whether id is one of the seven method ids. */
    public static boolean known(String id) {
        return id != null && IDS.contains(id);
    }

    /** Canonical position of id, -1 for anything else. */
    static int rank(String id) {
        return id == null ? -1 : IDS.indexOf(id);
    }

    /**
     * The method an amr value stands for. {@code inv} (a setup-link
     * session) and every value outside the table stand for nothing.
     */
    public static Optional<String> forAmr(String amr) {
        if (amr == null) {
            return Optional.empty();
        }
        for (Info i : TABLE) {
            if (i.amr().equals(amr)) {
                return Optional.of(i.id());
            }
        }
        return Optional.empty();
    }

    /** The amr value of method m (the reference value its execution carries). */
    public static String amrOf(String m) {
        for (Info i : TABLE) {
            if (i.id().equals(m)) {
                return i.amr();
            }
        }
        throw new IllegalArgumentException("not a sign-in method");
    }

    /** The strength of method m in tenths (10, 15, 25, 25, 30, 35, 40). */
    public static int tenths(String m) {
        for (Info i : TABLE) {
            if (i.id().equals(m)) {
                return i.tenths();
            }
        }
        throw new IllegalArgumentException("not a sign-in method");
    }

    /**
     * The session's methods (contract §8.1 "Session methods"): the stock
     * amr — the user session's completed executions within their max age,
     * the {@code oidc-amr-mapper}'s own computation through
     * {@link AmrUtils} — each mapped through {@link #forAmr} and kept only
     * while its method is on in {@link SigninConfig#current()}. Anything
     * that can't be read counts as nothing.
     */
    public static Set<String> ofSession(RealmModel r, UserSessionModel u) {
        return ofSession(r, u, SigninConfig.current());
    }

    /** {@link #ofSession(RealmModel, UserSessionModel)} against a given file. */
    public static Set<String> ofSession(RealmModel r, UserSessionModel u, SigninConfig cfg) {
        return r == null || u == null ? new LinkedHashSet<>() : ofExecutions(r, u.getNote(Constants.AUTHENTICATORS_COMPLETED), cfg);
    }

    /**
     * The methods of the authentication in progress: the executions it has
     * completed so far, within their max age, as the authentication session
     * keeps them for its user session (Keycloak merges an SSO session's own
     * completed executions in when {@code auth-cookie} reuses it), mapped
     * like {@link #ofSession}. A forced re-authentication counts only what it
     * completed itself.
     */
    public static Set<String> ofAuthentication(RealmModel r, AuthenticationSessionModel a, SigninConfig cfg) {
        return r == null || a == null ? new LinkedHashSet<>() : ofExecutions(r, a.getUserSessionNotes().get(Constants.AUTHENTICATORS_COMPLETED), cfg);
    }

    private static Set<String> ofExecutions(RealmModel r, String note, SigninConfig cfg) {
        Set<String> out = new LinkedHashSet<>();
        if (cfg == null) {
            return out;
        }
        Map<String, Integer> executions;
        try {
            executions = AuthenticatorUtils.parseCompletedExecutions(note);
        } catch (RuntimeException e) {
            return out; // unreadable counts as nothing
        }
        if (executions == null || executions.isEmpty()) {
            return out;
        }
        for (String amr : AmrUtils.getAuthenticationExecutionReferences(executions, r)) {
            forAmr(amr).filter(cfg::on).ifPresent(out::add);
        }
        // Canonical order (weakest first), whatever the executions' order.
        Set<String> sorted = new LinkedHashSet<>();
        for (String m : IDS) {
            if (out.contains(m)) {
                sorted.add(m);
            }
        }
        return sorted;
    }
}
