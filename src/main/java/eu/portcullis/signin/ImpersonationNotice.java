package eu.portcullis.signin;

import eu.portcullis.signin.store.NoticeSeenStore;
import jakarta.ws.rs.core.Response;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;
import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * {@code portcullis-impersonation-notice} (contract §8.1 "The notice", D45):
 * the person's notice at their next sign-in that an administrator signed in
 * as them.
 *
 * <ul>
 * <li>{@link #requiredActionChallenge}: in an impersonated session ({@link
 * ImpersonationGuard#impersonated}) {@code ignore()} — the action stays for
 * the person, never shown to the administrator. Otherwise every notice in
 * {@code impersonation.json} for this person whose {@code ended} is after
 * their seen time ({@code PORTCULLIS_IMP_NOTICE_SEEN}), oldest first, one
 * {@link #line} each; the latest {@code ended} shown is kept in the
 * authentication note {@link #SHOWN_NOTE}. Nothing unseen: {@link
 * History#reapply} and {@code success()} silently. An unreadable file: the
 * generic text.</li>
 * <li>{@link #processAction} (Continue): the seen time moved forward to what
 * the page showed (in its own transaction, retried once, so two first
 * Continues racing never fail the sign-in; a failed write only warns) (never back; not at all after the generic text), then
 * {@link History#reapply} and {@code success()} (F12). In an impersonated
 * session (a crafted post): the refusal page, nothing stored, never
 * completed — Keycloak 26.8.1's {@code processRequireAction} has no
 * {@code IGNORE} branch.</li>
 * </ul>
 * Nothing is logged with a reason.
 */
final class ImpersonationNotice implements RequiredActionProvider {
    private static final Logger LOG = Logger.getLogger(ImpersonationNotice.class);

    static final String ID = ImpersonationResource.NOTICE_ACTION;
    static final String PAGE = "portcullis-impersonation-notice.ftl";
    static final String ATTRIBUTE = "portcullisNotice";
    /** The latest {@code ended} the page showed, epoch milliseconds (an authentication note). */
    static final String SHOWN_NOTE = "portcullis.notice.shown";

    private static final DateTimeFormatter WHEN = DateTimeFormatter.ofPattern("d MMM yyyy HH:mm", Locale.ENGLISH)
            .withZone(ZoneOffset.UTC);

    /** The person's seen time ({@code PORTCULLIS_IMP_NOTICE_SEEN}; a test gives its own). */
    interface Seen {
        /** Epoch milliseconds, or {@link NoticeSeenStore#NEVER}. */
        long seenUntil(KeycloakSession s, UserModel u);

        /** Moves it forward to until; never back. */
        void advance(KeycloakSession s, UserModel u, long until);
    }

    static final Seen TABLE = new Seen() {
        @Override
        public long seenUntil(KeycloakSession s, UserModel u) {
            return NoticeSeenStore.of(s).seenUntil(u.getId());
        }

        @Override
        public void advance(KeycloakSession s, UserModel u, long until) {
            String userId = u.getId();
            boolean stored = NoticeSeenStore.advanceInOwnTransaction(job -> KeycloakModelUtils.runJobInTransaction(
                    s.getKeycloakSessionFactory(), own -> job.accept(own.getProvider(JpaConnectionProvider.class).getEntityManager())),
                    userId, until);
            if (!stored) {
                LOG.warnf("portcullis: the notice's seen time for %s wasn't stored: it may be shown again", u.getUsername());
            }
        }
    };

    private final Supplier<ImpersonationFile> file;
    private final Seen seen;
    private final BiFunction<KeycloakSession, RealmModel, AuthenticationManager.AuthResult> identity;
    private final Function<String, String> env;

    ImpersonationNotice() {
        this(ImpersonationFile::current, TABLE, (s, r) -> AuthenticationManager.authenticateIdentityCookie(s, r, true));
    }

    ImpersonationNotice(Supplier<ImpersonationFile> file, Seen seen,
            BiFunction<KeycloakSession, RealmModel, AuthenticationManager.AuthResult> identity) {
        this(file, seen, identity, System::getenv);
    }

    ImpersonationNotice(Supplier<ImpersonationFile> file, Seen seen,
            BiFunction<KeycloakSession, RealmModel, AuthenticationManager.AuthResult> identity, Function<String, String> env) {
        this.file = file;
        this.seen = seen;
        this.identity = identity;
        this.env = env;
    }

    /**
     * "root signed in as you on 12 Nov 2026 14:02 UTC for 26 min: checking
     * quota. Apps opened: Gitea, Nextcloud." plus "Nextcloud keeps its own
     * session and may have stayed signed in longer." for each app with its
     * own session; "Apps opened: none." without apps. The minutes are from
     * {@code started} to {@code ended}, rounded up, at least 1.
     */
    static String line(ImpersonationFile.Notice n) {
        StringBuilder b = new StringBuilder();
        b.append(n.admin()).append(" signed in as you on ").append(WHEN.format(n.started())).append(" UTC for ")
                .append(minutes(n.started(), n.ended())).append(" min: ").append(n.reason()).append(". Apps opened: ");
        if (n.apps().isEmpty()) {
            b.append("none.");
        } else {
            b.append(String.join(", ", n.apps().stream().map(ImpersonationFile.App::name).toList())).append('.');
        }
        for (ImpersonationFile.App a : n.apps()) {
            if (a.ownSession()) {
                b.append(' ').append(a.name()).append(" keeps its own session and may have stayed signed in longer.");
            }
        }
        return b.toString();
    }

    static long minutes(Instant started, Instant ended) {
        long s = Math.max(0, Duration.between(started, ended).toMillis());
        return Math.max(1, (s + 59_999) / 60_000);
    }

    private Optional<Impersonation.Info> impersonated(RequiredActionContext c) {
        return ImpersonationGuard.impersonated(c.getSession(), c.getRealm(), c.getAuthenticationSession(), identity);
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext c) {
        Optional<Impersonation.Info> imp = impersonated(c);
        if (imp.isPresent()) {
            LOG.debugf("portcullis: impersonation %s: the notice is kept for the person", imp.get().id());
            c.ignore();
            return;
        }
        c.getAuthenticationSession().removeAuthNote(SHOWN_NOTE);
        ImpersonationFile f = file.get();
        UserModel user = c.getUser();
        if (f == ImpersonationFile.DENY) {
            show(c, NoticePage.generic());
            return;
        }
        long since = seen.seenUntil(c.getSession(), user);
        List<ImpersonationFile.Notice> unseen = new ArrayList<>(f.notices(user.getUsername()).stream()
                .filter(n -> n.ended().toEpochMilli() > since).toList());
        if (unseen.isEmpty()) {
            History.reapply(c);
            c.success();
            return;
        }
        unseen.sort(Comparator.comparing(ImpersonationFile.Notice::ended).thenComparing(ImpersonationFile.Notice::started));
        long latest = unseen.stream().mapToLong(n -> n.ended().toEpochMilli()).max().orElseThrow();
        c.getAuthenticationSession().setAuthNote(SHOWN_NOTE, Long.toString(latest));
        show(c, NoticePage.of(unseen.stream().map(ImpersonationNotice::line).toList()));
    }

    private static void show(RequiredActionContext c, NoticePage page) {
        c.challenge(c.form().setAttribute(ATTRIBUTE, page).createForm(PAGE));
    }

    @Override
    public void processAction(RequiredActionContext c) {
        Optional<Impersonation.Info> imp = impersonated(c);
        if (imp.isPresent()) {
            LOG.infof("portcullis: impersonation %s: the notice can't be completed in an impersonated session", imp.get().id());
            UserModel user = c.getUser();
            String person = user == null ? null : user.getUsername();
            String stop = Impersonation.stopUrl(env);
            org.keycloak.forms.login.LoginFormsProvider forms = c.form();
            ImpersonationBanner banner = ImpersonationBanner.of(imp.get(), person, stop, Instant.now());
            if (banner != null) {
                forms.setAttribute(ImpersonationResource.BANNER, banner);
            }
            c.challenge(forms.setAttribute(ImpersonationResource.ATTRIBUTE, ImpersonatingPage.refused(person, stop))
                    .setStatus(Response.Status.FORBIDDEN).createForm(ImpersonationResource.PAGE));
            return;
        }
        String shown = c.getAuthenticationSession().getAuthNote(SHOWN_NOTE);
        if (shown != null) {
            c.getAuthenticationSession().removeAuthNote(SHOWN_NOTE);
            try {
                seen.advance(c.getSession(), c.getUser(), Long.parseLong(shown));
            } catch (NumberFormatException e) {
                LOG.warnf("portcullis: the notice's shown time for %s is unreadable: not stored", c.getUser().getUsername());
            }
        }
        History.reapply(c);
        c.success();
    }

    @Override
    public void evaluateTriggers(RequiredActionContext c) {
        // Only the Hub adds it (RequireImpersonationNotice).
    }

    @Override
    public void close() {
        // nothing held
    }
}
