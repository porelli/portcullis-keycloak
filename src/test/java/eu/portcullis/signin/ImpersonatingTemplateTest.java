package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** portcullis-impersonating.ftl: the three modes, the banner and Stop, every value escaped (D42, D43). */
class ImpersonatingTemplateTest {
    static final String STOP = "https://people.example.com/impersonation/stop";
    static final String AGAIN = "https://auth.example.com/realms/portcullis/protocol/openid-connect/auth?client_id=x";
    static final Instant NOW = Instant.parse("2026-11-12T14:10:00Z");

    private static String render(ImpersonatingPage page, ImpersonationBanner banner) throws Exception {
        Map<String, Object> attrs = new java.util.HashMap<>();
        attrs.put(ImpersonationResource.ATTRIBUTE, page);
        if (banner != null) {
            attrs.put(ImpersonationResource.BANNER, banner);
        }
        return NeedsStrongerTemplateTest.render(ImpersonationResource.PAGE, attrs).replaceAll("\\s+", " ");
    }

    private static ImpersonationBanner banner(String reason) {
        return ImpersonationBanner.of(new Impersonation.Info(ImpersonationFileTest.ID, "root", reason, NOW.plusSeconds(26 * 60 + 5)),
                "alice", STOP, NOW);
    }

    @Test
    void refusedAtStartHasNoBanner() throws Exception {
        String html = render(ImpersonatingPage.refusedStart(STOP), null);
        assertTrue(html.contains("id=\"impersonating\""), html);
        assertTrue(html.contains("This sign-in-as link can&#39;t be used"), html);
        assertFalse(html.contains("You are signed in as"), html);
    }

    @Test
    void bannerInEveryMode() throws Exception {
        for (ImpersonatingPage page : List.of(ImpersonatingPage.refused("alice", STOP),
                ImpersonatingPage.needs("Gitea", List.of("security_key", "yubikey_cert"), "root", "alice", STOP))) {
            String html = render(page, banner("checking quota"));
            assertTrue(html.contains("You are signed in as alice (by root) · reason “checking quota” · 27 min left"), html);
            assertTrue(html.contains("href=\"" + STOP + "\""), html);
            assertTrue(html.contains(">Stop</a>"), html);
        }
        String refused = render(ImpersonatingPage.refused("alice", STOP), banner("x y z"));
        assertTrue(refused.contains("Not while you are signed in as alice"), refused);
        String ended = render(ImpersonatingPage.ended("alice", AGAIN), null);
        assertTrue(ended.contains("Your session as alice has ended."), ended);
        // Ended: Sign in again (the authorize again), never Stop.
        assertTrue(ended.contains("href=\"" + AGAIN + "\">Sign in again</a>"), ended);
        assertFalse(ended.contains(">Stop</a>"), ended);
        String needs = render(ImpersonatingPage.needs("Gitea", List.of("security_key", "yubikey_cert"), "root", "alice", STOP), null);
        assertTrue(needs.contains("Gitea needs a security key or a YubiKey certificate. root&#39;s sign-in didn&#39;t use them, and a session as alice can&#39;t add one: Stop, sign in with them, and start again."), needs);
    }

    @Test
    void escapesValues() throws Exception {
        String html = render(ImpersonatingPage.ended("<i>", AGAIN), banner("<script>x</script> & \"q\""));
        assertFalse(html.contains("<script>"), html);
        assertFalse(html.contains("<i>"), html);
        assertTrue(html.contains("&lt;script&gt;x&lt;/script&gt; &amp; &quot;q&quot;"), html);
        // No Stop URL configured: no link, nothing broken.
        String none = render(ImpersonatingPage.ended("alice", null), null);
        assertFalse(none.contains("href="), none);
    }

    @Test
    void minutesLeftAtLeastOne() {
        ImpersonationBanner b = ImpersonationBanner.of(new Impersonation.Info(ImpersonationFileTest.ID, "root", "abc", NOW.plusSeconds(1)),
                "alice", STOP, NOW);
        assertTrue(b.getMinutesLeft() == 1);
        ImpersonationBanner past = ImpersonationBanner.of(new Impersonation.Info(ImpersonationFileTest.ID, "root", "abc", NOW.minusSeconds(100)),
                "alice", STOP, NOW);
        assertTrue(past.getMinutesLeft() == 1);
        ImpersonationBanner sixty = ImpersonationBanner.of(new Impersonation.Info(ImpersonationFileTest.ID, "root", "abc", NOW.plusSeconds(120)),
                "alice", STOP, NOW);
        assertTrue(sixty.getMinutesLeft() == 2);
    }

    @Test
    void stopUrlFromSigninOrigin() {
        Map<String, String> env = Map.of(TemplateAuthenticator.SIGNIN_URL_ENV, "https://people.example.com/signin");
        assertTrue(STOP.equals(Impersonation.stopUrl(env::get)));
        assertTrue(Impersonation.stopUrl(k -> null) == null);
        assertTrue(Impersonation.stopUrl(k -> "javascript:alert(1)") == null);
        assertTrue("http://localhost:18083/impersonation/stop".equals(Impersonation.stopUrl(k -> "http://localhost:18083/signin?x=1")));
    }

    @Test
    void neverUnescapes() throws Exception {
        String ftl = Files.readString(Path.of("src/main/resources/theme-resources/templates", ImpersonationResource.PAGE));
        assertFalse(ftl.contains("?no_esc"));
        assertFalse(ftl.contains("?html"));
        assertFalse(ftl.contains("noautoesc"));
    }
}
