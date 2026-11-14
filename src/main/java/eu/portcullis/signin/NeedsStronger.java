package eu.portcullis.signin;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * What {@code portcullis-needs-stronger.ftl} shows (contract §8.1 "Native-OIDC
 * apps", the copy of mockup {@code signin-people.html} section 2): the app,
 * the methods the person signed in with, one line per alternative of the
 * template, and the set-up links (all to the Sign-in page,
 * {@link TemplateAuthenticator#signinPage}). The template renders the method phrases
 * from message keys ({@code portcullisMethod_<id>}); every value goes
 * through FreeMarker's HTML auto-escaping.
 */
public final class NeedsStronger {
    /**
     * The form attribute of the impersonation banner ({@link ImpersonationBanner},
     * D43): the template shows it whenever it is set. In practice an
     * impersonated session never reaches this page — {@code portcullis-template}
     * shows {@code portcullis-impersonating.ftl} mode {@code needs} instead —
     * so the banner is the page's own guarantee.
     */
    public static final String BANNER = ImpersonationResource.BANNER;

    /** One alternative: its methods, and whether it needs a passkey kind or a code the person hasn't set up. */
    public static final class Line {
        private final List<String> methods;
        private final boolean notSetUp;

        Line(List<String> methods, boolean notSetUp) {
            this.methods = List.copyOf(methods);
            this.notSetUp = notSetUp;
        }

        public List<String> getMethods() {
            return methods;
        }

        public boolean isNotSetUp() {
            return notSetUp;
        }
    }

    private final String app;
    private final List<String> signedIn;
    private final List<Line> alternatives;
    private final boolean setUpPasskey;
    private final boolean setUpSecurityKey;
    private final boolean setUpAuthenticator;
    private final boolean askAdmin;
    private final String signinUrl;

    NeedsStronger(String app, List<String> signedIn, List<Line> alternatives, boolean setUpPasskey,
            boolean setUpSecurityKey, boolean setUpAuthenticator, boolean askAdmin, String signinUrl) {
        this.app = app;
        this.signedIn = List.copyOf(signedIn);
        this.alternatives = List.copyOf(alternatives);
        this.setUpPasskey = setUpPasskey;
        this.setUpSecurityKey = setUpSecurityKey;
        this.setUpAuthenticator = setUpAuthenticator;
        this.askAdmin = askAdmin;
        this.signinUrl = signinUrl;
    }

    /**
     * The page for a rule the session doesn't meet. A passkey kind the person
     * lacks gets a set-up link ("Set up a passkey" for synced / device-bound,
     * "Set up a security key") while {@code add_stronger} is on or the kind is
     * no stronger than the session's strongest method; a missing {@code totp}
     * the person hasn't set up gets "Set up an authenticator app" the same way
     * (T16: add_stronger on, or 1.5 no stronger than the session); otherwise,
     * and always for passwords and certificates, the page says "ask your
     * admin". {@code setUp} holds the methods the person has set up
     * ({@link TemplateAuthenticator#setUp}).
     */
    static NeedsStronger of(String app, Set<String> have, List<Set<String>> alternatives, Set<String> setUp,
            boolean addStronger, String signinUrl) {
        int strongest = 0;
        for (String m : have) {
            strongest = Math.max(strongest, Methods.tenths(m));
        }
        List<Line> lines = new ArrayList<>(alternatives.size());
        Set<String> missingAll = new LinkedHashSet<>();
        for (Set<String> alt : alternatives) {
            boolean notSetUp = false;
            for (String m : alt) {
                if (have.contains(m)) {
                    continue;
                }
                missingAll.add(m);
                if (settable(m) && !setUp.contains(m)) {
                    notSetUp = true;
                }
            }
            lines.add(new Line(sorted(alt), notSetUp));
        }
        boolean passkey = false;
        boolean securityKey = false;
        boolean authenticator = false;
        boolean askAdmin = false;
        for (String m : missingAll) {
            if (!settable(m)) {
                askAdmin = true; // passwords and certificates: only an admin sets them up
                continue;
            }
            if (setUp.contains(m)) {
                continue;
            }
            if (addStronger || Methods.tenths(m) <= strongest) {
                if (OtpAuthenticator.TOTP.equals(m)) {
                    authenticator = true;
                } else if ("security_key".equals(m)) {
                    securityKey = true;
                } else {
                    passkey = true;
                }
            } else {
                askAdmin = true;
            }
        }
        return new NeedsStronger(app, sorted(have), lines, passkey, securityKey, authenticator, askAdmin, signinUrl);
    }

    /** Methods a person sets up on the Sign-in page: the passkey kinds and an authenticator app. */
    private static boolean settable(String m) {
        return Methods.PASSKEY_KINDS.contains(m) || OtpAuthenticator.TOTP.equals(m);
    }

    private static List<String> sorted(Set<String> methods) {
        List<String> out = new ArrayList<>(methods.size());
        for (String m : Methods.IDS) {
            if (methods.contains(m)) {
                out.add(m);
            }
        }
        return out;
    }

    public String getApp() {
        return app;
    }

    public List<String> getSignedIn() {
        return signedIn;
    }

    public List<Line> getAlternatives() {
        return alternatives;
    }

    public boolean isSetUpPasskey() {
        return setUpPasskey;
    }

    public boolean isSetUpSecurityKey() {
        return setUpSecurityKey;
    }

    public boolean isSetUpAuthenticator() {
        return setUpAuthenticator;
    }

    public boolean isAskAdmin() {
        return askAdmin;
    }

    public String getSigninUrl() {
        return signinUrl;
    }
}
