package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import freemarker.cache.ClassTemplateLoader;
import freemarker.cache.MultiTemplateLoader;
import freemarker.cache.StringTemplateLoader;
import freemarker.cache.TemplateLoader;
import freemarker.core.HTMLOutputFormat;
import freemarker.core.TemplateClassResolver;
import freemarker.template.Configuration;
import freemarker.template.TemplateMethodModelEx;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * portcullis-needs-stronger.ftl rendered the way Keycloak renders a login
 * form: FreeMarker 2.3.32 rules with the HTML output format (auto-escaping),
 * no new built-in classes, the theme's {@code template.ftl} (stubbed here:
 * its layout macro prints the sections) and {@code msg} (MessageFormat over
 * the jar's messages_en.properties).
 */
class NeedsStrongerTemplateTest {
    static String render(NeedsStronger page) throws Exception {
        return render(TemplateAuthenticator.PAGE, Map.of(TemplateAuthenticator.ATTRIBUTE, page));
    }

    /** The jar's template name rendered with these attributes (plus msg and properties). */
    static String render(String name, Map<String, Object> attributes) throws Exception {
        Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
        cfg.setOutputFormat(HTMLOutputFormat.INSTANCE);
        cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
        StringTemplateLoader stub = new StringTemplateLoader();
        stub.putTemplate("template.ftl", "<#macro registrationLayout displayMessage=true>"
                + "<h1><#nested \"header\"></h1><main><#nested \"form\"></main></#macro>");
        cfg.setTemplateLoader(new MultiTemplateLoader(new TemplateLoader[] {
            stub, new ClassTemplateLoader(NeedsStrongerTemplateTest.class, "/theme-resources/templates")}));
        Properties messages = new Properties();
        try (InputStream in = NeedsStrongerTemplateTest.class.getResourceAsStream("/theme-resources/messages/messages_en.properties")) {
            messages.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        TemplateMethodModelEx msg = args -> {
            String key = args.get(0).toString();
            String pattern = messages.getProperty(key);
            if (pattern == null) {
                throw new IllegalArgumentException("no message " + key);
            }
            Object[] params = new Object[args.size() - 1];
            for (int i = 1; i < args.size(); i++) {
                params[i - 1] = args.get(i).toString();
            }
            return new MessageFormat(pattern, Locale.ENGLISH).format(params);
        };
        Map<String, Object> model = new HashMap<>(attributes);
        model.put("msg", msg);
        model.put("properties", Map.of("kcButtonPrimaryClass", "pf-primary", "kcButtonDefaultClass", "pf-default"));
        StringWriter out = new StringWriter();
        cfg.getTemplate(name, "UTF-8").process(model, out);
        return out.toString();
    }

    private static List<Set<String>> standard() {
        return List.of(Set.of("passkey_synced"), Set.of("passkey_device"), Set.of("security_key"), Set.of("yubikey_cert"));
    }

    @Test
    void escapesValues() throws Exception {
        NeedsStronger page = NeedsStronger.of("<b>", Set.of(), standard(), Set.of(), false,
                "https://auth.example.com/realms/portcullis/account/\"><script>x</script>");
        String html = render(page);
        assertTrue(html.contains("&lt;b&gt; needs a stronger sign-in"), html);
        assertTrue(html.contains("&lt;b&gt; accepts any one of:"), html);
        assertFalse(html.contains("<b> needs"), html);
        assertFalse(html.contains("<script>"), html);
        assertTrue(html.contains("&quot;&gt;&lt;script&gt;"), html);
    }

    @Test
    void copiesTheMockup() throws Exception {
        // Mockup section 2: a password session, an app accepting a passkey or a YubiKey certificate.
        String acct = "https://auth.example.com/realms/portcullis/account/account-security/signing-in";
        NeedsStronger page = NeedsStronger.of("Gitea", Set.of("password"),
                List.of(Set.of("passkey_synced"), Set.of("yubikey_cert")), Set.of(), true, acct);
        String html = render(page).replaceAll("\\s+", " ");
        assertTrue(html.contains("Gitea needs a stronger sign-in"), html);
        assertTrue(html.contains("You signed in with a <b>password</b>. Gitea accepts any one of:"), html);
        assertTrue(html.contains("<li>a passkey <span class=\"portcullis-sub\">— you don&#39;t have one yet</span></li>"), html);
        assertTrue(html.contains("<li>a YubiKey certificate</li>"), html);
        assertTrue(html.contains("id=\"needs-stronger\""), html);
        assertTrue(html.contains("href=\"" + acct + "\">Set up a passkey</a>"), html);
        assertTrue(html.contains(">Sign-in methods</a>"), html);
        assertTrue(html.contains("or ask your admin"), html);
        assertFalse(html.contains("Set up a security key"), html);
    }

    @Test
    void namesBothCertificates() throws Exception {
        // D34: "YubiKey certificate" and "Browser certificate"; every link is the Sign-in page.
        String signin = "https://people.example.com/signin";
        NeedsStronger page = NeedsStronger.of("Gitea", Set.of("passkey_synced"),
                List.of(Set.of("yubikey_cert"), Set.of("browser_cert")), Set.of(), false, signin);
        String html = render(page).replaceAll("\\s+", " ");
        assertTrue(html.contains("<li>a YubiKey certificate</li>"), html);
        assertTrue(html.contains("<li>a browser certificate</li>"), html);
        assertTrue(html.contains("href=\"" + signin + "\">Sign-in methods</a>"), html);
        assertTrue(html.contains("or ask your admin"), html);
        assertFalse(html.toLowerCase(Locale.ROOT).contains("mtls"), html);
        assertFalse(html.toLowerCase(Locale.ROOT).contains("client certificate"), html);
    }

    @Test
    void neverUnescapes() throws Exception {
        String ftl = Files.readString(Path.of("src/main/resources/theme-resources/templates", TemplateAuthenticator.PAGE));
        assertFalse(ftl.contains("?no_esc"));
        assertFalse(ftl.contains("?html"));
        assertFalse(ftl.contains("noautoesc"));
    }
}
