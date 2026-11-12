package eu.portcullis.signin;

import java.util.List;

/**
 * What {@code portcullis-impersonating.ftl} shows (contract §8.1
 * "Impersonation", D42): the mode — {@code refused}, {@code ended} or
 * {@code needs} — and its values; Stop links to {@link #getStopUrl()}. The
 * banner is the separate attribute {@link ImpersonationBanner}. Every value
 * goes through FreeMarker's HTML auto-escaping.
 */
public final class ImpersonatingPage {
    static final String REFUSED = "refused";
    static final String ENDED = "ended";
    static final String NEEDS = "needs";

    private final String mode;
    private final boolean start;
    private final String person;
    private final String admin;
    private final String app;
    private final List<String> methods;
    private final String stopUrl;

    private ImpersonatingPage(String mode, boolean start, String person, String admin, String app, List<String> methods, String stopUrl) {
        this.mode = mode;
        this.start = start;
        this.person = person;
        this.admin = admin;
        this.app = app;
        this.methods = List.copyOf(methods);
        this.stopUrl = stopUrl;
    }

    /** The start refused: "This sign-in-as link can't be used …" (why is only in the log). */
    static ImpersonatingPage refusedStart(String stopUrl) {
        return new ImpersonatingPage(REFUSED, true, null, null, null, List.of(), stopUrl);
    }

    /** "Not while you are signed in as &lt;person&gt;". */
    static ImpersonatingPage refused(String person, String stopUrl) {
        return new ImpersonatingPage(REFUSED, false, person, null, null, List.of(), stopUrl);
    }

    /** "Your session as &lt;person&gt; has ended." */
    static ImpersonatingPage ended(String person, String stopUrl) {
        return new ImpersonatingPage(ENDED, false, person, null, null, List.of(), stopUrl);
    }

    /** "&lt;App&gt; needs &lt;methods&gt;. &lt;admin&gt;'s sign-in didn't use them, …" (D39). */
    static ImpersonatingPage needs(String app, List<String> methods, String admin, String person, String stopUrl) {
        return new ImpersonatingPage(NEEDS, false, person, admin, app, methods, stopUrl);
    }

    public String getMode() {
        return mode;
    }

    /** Whether this is the start's refusal (no impersonation running in this browser). */
    public boolean isStart() {
        return start;
    }

    public String getPerson() {
        return person;
    }

    public String getAdmin() {
        return admin;
    }

    public String getApp() {
        return app;
    }

    /** The method ids the app accepts (mode {@code needs}). */
    public List<String> getMethods() {
        return methods;
    }

    /** Stop ({@link Impersonation#stopUrl}); null: no link. */
    public String getStopUrl() {
        return stopUrl;
    }
}
