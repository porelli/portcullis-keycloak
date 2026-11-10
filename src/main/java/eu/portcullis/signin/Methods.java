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
            new Info("passkey_synced", "spk", 25),
            new Info("browser_cert", "file", 25),
            new Info("passkey_device", "dpk", 30),
            new Info("security_key", "hwk", 35),
            new Info("yubikey_cert", "mtls", 40));

    /** The six method ids, in canonical order. */
    public static final List<String> IDS = TABLE.stream().map(Info::id).toList();

    /** Methods that can't be switched on yet: off whatever the file says. */
    static final Set<String> UNAVAILABLE = Set.of("browser_cert");

    /** Whether id is one of the six method ids. */
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

    /** The strength of method m in tenths (10, 25, 25, 30, 35, 40). */
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
        Set<String> out = new LinkedHashSet<>();
        if (r == null || u == null) {
            return out;
        }
        Map<String, Integer> executions = AuthenticatorUtils.parseCompletedExecutions(u.getNote(Constants.AUTHENTICATORS_COMPLETED));
        if (executions == null || executions.isEmpty()) {
            return out;
        }
        SigninConfig cfg = SigninConfig.current();
        for (String amr : AmrUtils.getAuthenticationExecutionReferences(executions, r)) {
            forAmr(amr).filter(cfg::on).ifPresent(out::add);
        }
        return out;
    }
}
