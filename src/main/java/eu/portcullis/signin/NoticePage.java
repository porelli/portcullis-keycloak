package eu.portcullis.signin;

import java.util.List;

/**
 * What {@code portcullis-impersonation-notice.ftl} shows (contract §8.1 "The
 * notice", D45): one line per unseen impersonation ({@link
 * ImpersonationNotice#line}), or — when {@code impersonation.json} can't be
 * read — the generic text. Every value goes through FreeMarker's HTML
 * auto-escaping.
 */
public final class NoticePage {
    private final List<String> lines;
    private final boolean generic;

    private NoticePage(List<String> lines, boolean generic) {
        this.lines = List.copyOf(lines);
        this.generic = generic;
    }

    static NoticePage of(List<String> lines) {
        return new NoticePage(lines, false);
    }

    /** "An administrator signed in as you. Your Sign-in page's history has the details." */
    static NoticePage generic() {
        return new NoticePage(List.of(), true);
    }

    public List<String> getLines() {
        return lines;
    }

    public boolean isGeneric() {
        return generic;
    }
}
