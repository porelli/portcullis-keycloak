package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.events.EventType;
import org.keycloak.models.Constants;
import org.keycloak.models.UserModel;

/** The CONFIGURE_TOTP override (contract §8.1 "Authenticator-app codes"). */
class TotpRegisterTest {
    private static final SigninConfig ON = Configs.of(Configs.WITH_TOTP, false, "", "");
    private static final SigninConfig ON_STRONGER = Configs.of(Configs.WITH_TOTP, true, "", "");
    private static final SigninConfig OFF = Configs.of(Configs.WITH_PASSWORD, false, "", "");
    private static final String OWN = "9c1f6a0e-2b7d-4e43-9a51-0f3c2d6b8e11";
    private static final Set<String> NONE = Set.of();

    private static TotpRegister.Decision decide(Set<String> amr, boolean addStronger, SigninConfig cfg, String user, int existing,
            Optional<String> replace, Set<String> own) {
        return TotpRegister.decide(amr, addStronger, cfg, user, existing, replace, own);
    }

    private static void assertRefused(String key, TotpRegister.Decision d) {
        assertFalse(d.allowed(), key);
        assertEquals(key, d.messageKey());
        assertNull(d.replaceId());
    }

    // ── decide ──

    @Test
    void offRefused() {
        assertRefused(TotpRegister.OFF, decide(Set.of("hwk"), true, OFF, "alice", 0, Optional.empty(), NONE));
        assertRefused(TotpRegister.OFF, decide(Set.of("hwk"), true, SigninConfig.DENY_ALL, "alice", 0, Optional.empty(), NONE));
        assertRefused(TotpRegister.OFF, decide(Set.of("hwk"), true, null, "alice", 0, Optional.empty(), NONE));
    }

    @Test
    void reservedRefused() {
        for (String name : new String[] {"admin", "portcullis-hub", "Admin", " portcullis-hub "}) {
            assertRefused(TotpRegister.NOT_AVAILABLE, decide(Set.of("hwk"), true, ON, name, 0, Optional.empty(), NONE));
        }
        assertRefused(TotpRegister.NOT_AVAILABLE, decide(Set.of("hwk"), true, ON, null, 0, Optional.empty(), NONE));
        // L4: every portcullis-* account, as the Hub's inventory.
        for (String name : new String[] {"portcullis-mcp", " Portcullis-x ", "PORTCULLIS-enroll"}) {
            assertRefused(TotpRegister.NOT_AVAILABLE, decide(Set.of("hwk"), true, ON, name, 0, Optional.empty(), NONE));
            assertTrue(OtpAuthenticator.reserved(name), name);
        }
        assertFalse(OtpAuthenticator.reserved("portcullis"), "the prefix needs its dash");
        assertFalse(OtpAuthenticator.reserved("alice"));
    }

    @Test
    void capRefusesPasswordOnly() {
        assertRefused(TotpRegister.STRONGER, decide(Set.of("pwd"), false, ON, "alice", 0, Optional.empty(), NONE));
        assertRefused(TotpRegister.STRONGER, decide(Set.of(), false, ON, "alice", 0, Optional.empty(), NONE));
        // A switched-off method counts as nothing.
        assertRefused(TotpRegister.STRONGER, decide(Set.of("pwd", "hwk"), false,
                Configs.of("\"password\", \"totp\"", false, "", ""), "alice", 0, Optional.empty(), NONE));
        // P29's mirror: a pwd+otp session (1.5) still can't add a passkey.
        assertFalse(PasskeyRegister.cap(Set.of("pwd", "otp"), "passkey_synced", false, ON).allowed());
    }

    @Test
    void capAllowsPasswordAndCode() {
        assertTrue(decide(Set.of("pwd", "otp"), false, ON, "alice", 1, Optional.empty(), Set.of(OWN)).allowed());
    }

    @Test
    void capAllowsSyncedPasskey() {
        assertTrue(decide(Set.of("spk"), false, ON, "alice", 0, Optional.empty(), NONE).allowed());
        assertTrue(decide(Set.of("mtls"), false, ON, "alice", 0, Optional.empty(), NONE).allowed());
        assertRefused(TotpRegister.STRONGER, decide(Set.of("file"), false, ON, "alice", 0, Optional.empty(), NONE)); // browser_cert off
        SigninConfig browser = Configs.of("\"browser_cert\", \"password\", \"totp\"", false, "", "");
        assertTrue(decide(Set.of("file"), false, browser, "alice", 0, Optional.empty(), NONE).allowed());
    }

    @Test
    void setupLinkNoCap() {
        assertTrue(decide(Set.of("inv"), false, ON, "alice", 0, Optional.empty(), NONE).allowed());
    }

    @Test
    void addStrongerOnNoCap() {
        assertTrue(decide(Set.of("pwd"), true, ON_STRONGER, "alice", 0, Optional.empty(), NONE).allowed());
        assertTrue(decide(Set.of(), true, ON_STRONGER, "alice", 0, Optional.empty(), NONE).allowed());
    }

    @Test
    void fourthRefused() {
        assertTrue(decide(Set.of("hwk"), false, ON, "alice", 2, Optional.empty(), NONE).allowed());
        assertRefused(TotpRegister.LIMIT, decide(Set.of("hwk"), false, ON, "alice", 3, Optional.empty(), NONE));
        assertRefused(TotpRegister.LIMIT, decide(Set.of("hwk"), false, ON, "alice", 4, Optional.empty(), NONE));
        assertEquals(3, TotpRegister.MAX);
    }

    @Test
    void replaceAtLimitAllowed() {
        Set<String> own = Set.of(OWN, "a2", "a3");
        TotpRegister.Decision d = decide(Set.of("hwk"), false, ON, "alice", 3, Optional.of(OWN), own);
        assertTrue(d.allowed());
        assertEquals(OWN, d.replaceId());
    }

    @Test
    void replaceForeignRefused() {
        Set<String> own = Set.of(OWN);
        for (String p : new String[] {"5b2e0c55-1d0e-4a8f-9c3e-77a1b2c3d4e5", "webauthn-passwordless-0", "garbage", "", "replace",
                "replace:" + OWN, OWN.toUpperCase(), OWN + " "}) {
            assertRefused(TotpRegister.REPLACE_UNKNOWN, decide(Set.of("hwk"), false, ON, "alice", 1, Optional.of(p), own));
        }
        assertRefused(TotpRegister.REPLACE_UNKNOWN, decide(Set.of("hwk"), false, ON, "alice", 1, Optional.of(OWN), null));
    }

    @Test
    void unknownParameterRefused() {
        assertRefused(TotpRegister.REPLACE_UNKNOWN, decide(Set.of("hwk"), false, ON, "alice", 0, Optional.of("foo"), NONE));
        // The switch and the cap still come first.
        assertRefused(TotpRegister.OFF, decide(Set.of("hwk"), false, OFF, "alice", 0, Optional.of("foo"), NONE));
        assertRefused(TotpRegister.STRONGER, decide(Set.of("pwd"), false, ON, "alice", 1, Optional.of(OWN), Set.of(OWN)));
    }

    // ── The action, over Fake contexts ──

    /** A RequiredActionContext over a Flow (the sign-in that reached the action). */
    private static final class Action {
        final Flow flow = new Flow();
        final Flow.Person person;
        RequiredActionContext.Status status;
        final RequiredActionContext context;
        /** The UPDATE_CREDENTIAL's details as Keycloak sends it (the stock event.success()). */
        Map<String, String> sent;
        boolean stockChallenged;
        boolean stockPosted;

        /** The request's transaction (setRollbackOnly recorded). */
        final Fake tx = Fake.named("transaction");

        Action(String username, String... amrs) {
            flow.sessionFake.ret("getTransactionManager", tx.as(org.keycloak.models.KeycloakTransactionManager.class));
            person = flow.person("u-" + username.trim(), username);
            flow.user = person.model;
            flow.completed(amrs);
            context = Fake.named("required action")
                    .on("getAuthenticationSession", a -> flow.authSession)
                    .on("getEvent", a -> flow.event)
                    .on("getUser", a -> person.model)
                    .on("success", a -> status = RequiredActionContext.Status.SUCCESS)
                    .on("challenge", a -> status = RequiredActionContext.Status.CHALLENGE)
                    .on("getStatus", a -> status)
                    .on("getSession", a -> flow.session)
                    .on("getRealm", a -> flow.realm)
                    .on("getUriInfo", a -> flow.context.getUriInfo())
                    .on("getHttpRequest", a -> flow.context.getHttpRequest())
                    .on("form", a -> flow.context.form())
                    .as(RequiredActionContext.class);
            History.onSuccess(flow.context, Set.of("security_key"), Set.of("security_key"), "sign_in");
        }

        /** As the application-initiated action, with this parameter (null: none). */
        Action initiated(String parameter) {
            flow.clientNotes.put(Constants.KC_ACTION, "CONFIGURE_TOTP");
            if (parameter != null) {
                flow.clientNotes.put(Constants.KC_ACTION_PARAMETER, parameter);
            }
            return this;
        }

        /** The override, with the stock code stubbed: the challenge noted, a post stores newId / newLabel. */
        TotpRegister register(SigninConfig cfg, String newId, String newLabel,
                java.util.function.BiFunction<org.keycloak.models.KeycloakSession, org.keycloak.models.RealmModel,
                        org.keycloak.services.managers.AuthenticationManager.AuthResult> identity) {
            return new TotpRegister(identity, k -> "PORTCULLIS_SIGNIN_URL".equals(k) ? "https://people.example.com/signin" : null, () -> cfg) {
                @Override
                void stockChallenge(RequiredActionContext c) {
                    stockChallenged = true;
                    c.challenge(null);
                }

                @Override
                void stockProcess(RequiredActionContext c) {
                    stockPosted = true;
                    c.getEvent().event(EventType.UPDATE_CREDENTIAL).detail("credential_type", "otp");
                    person.otp(newId, newLabel);
                    c.success();
                    sent = new HashMap<>(flow.eventDetails());
                }
            };
        }

        TotpRegister register(SigninConfig cfg) {
            return register(cfg, "new-otp", "Authenticator 2026-11-14 10:00:00", (s, r) -> null);
        }
    }

    @Test
    void factoryMarker() {
        TotpRegisterFactory f = new TotpRegisterFactory();
        assertEquals("CONFIGURE_TOTP", f.getId());
        assertEquals(Map.of("portcullis", "totp"), f.getOperationalInfo());
        assertEquals(1, f.order());
        assertTrue(f.create(null) instanceof TotpRegister);
        assertTrue(f instanceof org.keycloak.authentication.requiredactions.UpdateTotp);
        // The account console's "Set up authenticator application" uses the action by this id.
        assertEquals(UserModel.RequiredAction.CONFIGURE_TOTP.name(), f.getId());
    }

    @Test
    void allowedRunsTheStockCode() {
        Action r = new Action("alice", "hwk").initiated(null);
        TotpRegister t = r.register(ON);
        t.requiredActionChallenge(r.context);
        assertTrue(r.stockChallenged);
        t.processAction(r.context);
        assertTrue(r.stockPosted);
        assertEquals(RequiredActionContext.Status.SUCCESS, r.status);
        assertEquals("Authenticator 2026-11-14 10:00:00", r.sent.get("credential_user_label"));
        assertEquals("new-otp", r.sent.get("credential_id"));
        assertEquals("otp", r.sent.get("credential_type"));
        assertFalse(r.sent.containsKey(TotpRegister.REPLACED), "an add, not a replace");
        // Keycloak sends the builder's UPDATE_CREDENTIAL after processAction: the details are still on it,
        // with the sign-in's history details back for the LOGIN that may follow.
        assertEquals("new-otp", r.flow.eventDetails().get("credential_id"));
        assertEquals("sign_in", r.flow.eventDetails().get(History.KIND));
    }

    @Test
    void impersonatedRefusedPage() {
        Action r = new Action("alice", "hwk").initiated(null);
        org.keycloak.models.UserSessionModel imp = Imp.alice(r.flow, r.person, "hwk");
        TotpRegister t = r.register(ON, "new-otp", "x",
                (s, realm) -> new org.keycloak.services.managers.AuthenticationManager.AuthResult(r.person.model, imp, null, null));
        t.requiredActionChallenge(r.context);
        assertFalse(r.stockChallenged, "no secret generated");
        assertEquals(RequiredActionContext.Status.CHALLENGE, r.status);
        assertEquals(ImpersonationResource.PAGE, r.flow.page);
        assertEquals(ImpersonatingPage.REFUSED, ((ImpersonatingPage) r.flow.formAttributes.get(ImpersonationResource.ATTRIBUTE)).getMode());
        assertEquals(List.of("not_allowed"), r.flow.eventErrors);
        assertEquals(EventType.UPDATE_CREDENTIAL, r.flow.event.getEvent().getType());
        t.processAction(r.context);
        assertFalse(r.stockPosted, "nothing stored");
        assertTrue(r.person.credentials.getOrDefault("otp", List.of()).isEmpty());

        // A setup link's (user) action while impersonated: refused too, and kept for the person's own sign-in.
        Action user = new Action("alice", "hwk");
        org.keycloak.models.UserSessionModel imp2 = Imp.alice(user.flow, user.person, "hwk");
        user.register(OFF, "n", "x", (s, realm) -> new org.keycloak.services.managers.AuthenticationManager.AuthResult(user.person.model, imp2, null, null))
                .requiredActionChallenge(user.context);
        assertEquals(RequiredActionContext.Status.CHALLENGE, user.status);
        assertFalse(user.person.fake.called("removeRequiredAction"), "an administrator's session never drops it");
    }

    @Test
    void challengeRefusesBeforeQr() {
        Action r = new Action("alice", "pwd").initiated(null);
        r.register(ON).requiredActionChallenge(r.context);
        assertFalse(r.stockChallenged, "the stock challenge never runs: no secret generated");
        assertEquals(RequiredActionContext.Status.CHALLENGE, r.status);
        assertEquals(TotpRegister.PAGE, r.flow.page);
        TotpRegister.Refusal page = (TotpRegister.Refusal) r.flow.formAttributes.get(TotpRegister.ATTRIBUTE);
        assertEquals(TotpRegister.STRONGER, page.getMessage());
        assertEquals("https://people.example.com/signin", page.getSigninUrl());
        assertEquals(List.of("not_allowed"), r.flow.eventErrors);
        // The post is refused the same way, nothing stored.
        Action post = new Action("alice", "pwd").initiated(null);
        post.register(ON).processAction(post.context);
        assertFalse(post.stockPosted);
        assertTrue(post.person.credentials.getOrDefault("otp", List.of()).isEmpty());
        // A fourth app; an unknown parameter.
        Action four = new Action("alice", "hwk").initiated(null);
        four.person.otp("o1", "a").otp("o2", "b").otp("o3", "c");
        four.register(ON).requiredActionChallenge(four.context);
        assertEquals(TotpRegister.LIMIT, ((TotpRegister.Refusal) four.flow.formAttributes.get(TotpRegister.ATTRIBUTE)).getMessage());
        Action foo = new Action("alice", "hwk").initiated("foo");
        foo.register(ON).requiredActionChallenge(foo.context);
        assertFalse(foo.stockChallenged);
        assertEquals(TotpRegister.REPLACE_UNKNOWN, ((TotpRegister.Refusal) foo.flow.formAttributes.get(TotpRegister.ATTRIBUTE)).getMessage());
    }

    /** P9: refused as a user required action (a setup link's): removed from the person, completed, nothing stored. */
    @Test
    void userActionRefusedIsRemovedNotLooped() {
        Action r = new Action("alice", "inv");
        r.register(OFF).requiredActionChallenge(r.context);
        assertFalse(r.stockChallenged);
        assertEquals(RequiredActionContext.Status.SUCCESS, r.status);
        assertTrue(r.person.fake.calls("removeRequiredAction").stream()
                .anyMatch(a -> a[0] == UserModel.RequiredAction.CONFIGURE_TOTP || "CONFIGURE_TOTP".equals(a[0])));
        assertTrue(r.person.credentials.getOrDefault("otp", List.of()).isEmpty());
        assertEquals("sign_in", r.flow.eventDetails().get(History.KIND), "the LOGIN keeps the sign-in's details");

        Action admin = new Action("admin", "inv");
        admin.register(ON).processAction(admin.context);
        assertFalse(admin.stockPosted);
        assertEquals(RequiredActionContext.Status.SUCCESS, admin.status);
        assertTrue(admin.person.fake.called("removeRequiredAction"));

        // Allowed (a setup-link session has no cap): the stock code runs.
        Action ok = new Action("alice", "inv");
        ok.register(ON).requiredActionChallenge(ok.context);
        assertTrue(ok.stockChallenged);
        assertFalse(ok.person.fake.called("removeRequiredAction"));
        // The application-initiated action's refusal is a page, never a removal.
        Action aia = new Action("alice", "pwd").initiated(null);
        aia.register(ON).requiredActionChallenge(aia.context);
        assertEquals(RequiredActionContext.Status.CHALLENGE, aia.status);
        assertFalse(aia.person.fake.called("removeRequiredAction"));
    }

    @Test
    void replaceDeletesOldInSameTransaction() {
        Action r = new Action("alice", "pwd", "otp").initiated(OWN);
        r.person.otp(OWN, "Old phone");
        r.register(ON).processAction(r.context);
        assertEquals(RequiredActionContext.Status.SUCCESS, r.status);
        List<String> ids = r.person.credentials.get("otp").stream().map(org.keycloak.credential.CredentialModel::getId).toList();
        assertEquals(List.of("new-otp"), ids, "the old one removed, the new one kept");
        assertEquals("Old phone", r.sent.get(TotpRegister.REPLACED));
        assertEquals("Authenticator 2026-11-14 10:00:00", r.sent.get("credential_user_label"));
        assertEquals("new-otp", r.sent.get("credential_id"));
        assertEquals("Old phone", r.flow.eventDetails().get(TotpRegister.REPLACED), "still on the builder Keycloak sends");
    }

    @Test
    void replaceGoneBetweenChallengeAndPost() {
        // Gone before the post: refused, the stock code never runs.
        Action r = new Action("alice", "hwk").initiated(OWN);
        r.person.otp(OWN, "Old phone");
        TotpRegister t = r.register(ON);
        t.requiredActionChallenge(r.context);
        assertTrue(r.stockChallenged);
        r.person.credentials.get("otp").clear();
        t.processAction(r.context);
        assertFalse(r.stockPosted, "nothing stored");
        assertEquals(TotpRegister.REPLACE_UNKNOWN, ((TotpRegister.Refusal) r.flow.formAttributes.get(TotpRegister.ATTRIBUTE)).getMessage());

        // Gone while the stock code stores the new one: an exception, the transaction rolls back.
        Action race = new Action("alice", "hwk").initiated(OWN);
        race.person.otp(OWN, "Old phone");
        TotpRegister racing = new TotpRegister((s, realm) -> null, k -> null, () -> ON) {
            @Override
            void stockProcess(RequiredActionContext c) {
                race.person.otp("new-otp", "New");
                race.person.credentials.get("otp").removeIf(x -> x.getId().equals(OWN)); // removed elsewhere meanwhile
                c.success();
            }
        };
        racing.processAction(race.context);
        assertEquals(RequiredActionContext.Status.CHALLENGE, race.status, "a refusal, never completed");
        assertTrue(race.tx.called("setRollbackOnly"), "the new credential is rolled back");
        assertEquals(TotpRegister.REPLACE_UNKNOWN, ((TotpRegister.Refusal) race.flow.formAttributes.get(TotpRegister.ATTRIBUTE)).getMessage());
        assertEquals(TotpRegister.PAGE, race.flow.page);

        // A replace id that names a passkey of theirs.
        Action passkey = new Action("alice", "hwk").initiated("webauthn-passwordless-0");
        passkey.person.passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s"));
        passkey.register(ON).requiredActionChallenge(passkey.context);
        assertFalse(passkey.stockChallenged);
    }

    /** L1: two adds at once past the limit: the later one is refused and rolled back. */
    @Test
    void concurrentAddOverTheLimitRolledBack() {
        Action r = new Action("alice", "hwk").initiated(null);
        r.person.otp("o1", "a").otp("o2", "b").otp("o3", "c"); // the other popup stored the third meanwhile
        TotpRegister t = new TotpRegister((s, realm) -> null, k -> null, () -> ON) {
            @Override
            Decision decide(RequiredActionContext c) {
                return Decision.allow(null); // what it decided when only two existed
            }

            @Override
            void stockProcess(RequiredActionContext c) {
                r.person.otp("new-otp", "d");
                c.success();
            }
        };
        t.processAction(r.context);
        assertEquals(RequiredActionContext.Status.CHALLENGE, r.status);
        assertTrue(r.tx.called("setRollbackOnly"));
        assertEquals(TotpRegister.LIMIT, ((TotpRegister.Refusal) r.flow.formAttributes.get(TotpRegister.ATTRIBUTE)).getMessage());
    }

    @Test
    void newCredentialMissingFailsClosed() {
        Action r = new Action("alice", "hwk").initiated(null);
        TotpRegister t = new TotpRegister((s, realm) -> null, k -> null, () -> ON) {
            @Override
            void stockProcess(RequiredActionContext c) {
                c.success(); // the stock code said success, but no credential is there
            }
        };
        assertThrows(IllegalStateException.class, () -> t.processAction(r.context));
    }

    @Test
    void logsNoSecret() {
        List<String> lines = new ArrayList<>();
        Handler h = new Handler() {
            @Override
            public void publish(LogRecord rec) {
                String msg = rec.getMessage();
                if (rec.getParameters() != null && msg != null) {
                    try {
                        msg = String.format(msg, rec.getParameters());
                    } catch (RuntimeException e) {
                        msg = msg + " " + java.util.Arrays.toString(rec.getParameters());
                    }
                }
                lines.add(String.valueOf(msg));
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };
        java.util.logging.Logger jul = java.util.logging.Logger.getLogger(TotpRegister.class.getName());
        jul.addHandler(h);
        jul.setLevel(java.util.logging.Level.ALL);
        String secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        try {
            Action r = new Action("alice", "pwd", "otp").initiated(OWN);
            r.person.otp(OWN, "Old phone");
            r.flow.form.add("totpSecret", secret);
            r.flow.form.add("totp", "123456");
            r.flow.form.add("userLabel", "Authenticator 2026-11-14 10:00:00");
            r.flow.authNotes.put("TOTP_SECRET_KEY", secret);
            TotpRegister t = r.register(ON);
            t.requiredActionChallenge(r.context);
            t.processAction(r.context);
            assertEquals(RequiredActionContext.Status.SUCCESS, r.status);
            Action refused = new Action("alice", "pwd").initiated("otpauth://totp/x?secret=" + secret);
            refused.flow.form.add("totpSecret", secret);
            refused.register(ON).processAction(refused.context);
            Action dropped = new Action("alice", "inv");
            dropped.register(OFF).processAction(dropped.context);
        } finally {
            jul.removeHandler(h);
        }
        assertTrue(lines.stream().anyMatch(l -> l.contains("authenticator app replaced for alice")), "the capture works: " + lines);
        assertTrue(lines.stream().anyMatch(l -> l.contains("refused")), lines.toString());
        for (String l : lines) {
            assertFalse(l.contains(secret), l);
            assertFalse(l.toLowerCase().contains("secret"), l);
            assertFalse(l.contains("otpauth:"), l);
            assertFalse(l.contains("123456"), l);
            assertFalse(java.util.regex.Pattern.compile("[A-Z2-7]{16,}").matcher(l).find(), l);
        }
    }

    @Test
    void refusalPageRenders() throws Exception {
        String html = NeedsStrongerTemplateTest.render(TotpRegister.PAGE, Map.of(TotpRegister.ATTRIBUTE,
                new TotpRegister.Refusal(TotpRegister.LIMIT, "https://people.example.com/signin?\"><script>"))).replaceAll("\\s+", " ");
        assertTrue(html.contains("you already have 3 authenticator apps: remove one first"), html);
        assertTrue(html.contains("Authenticator app not added"), html);
        assertTrue(html.contains("id=\"portcullis-sign-in-methods\""), html);
        assertFalse(html.contains("<script>"), html);
        for (String key : new String[] {TotpRegister.OFF, TotpRegister.NOT_AVAILABLE, TotpRegister.STRONGER, TotpRegister.REPLACE_UNKNOWN}) {
            NeedsStrongerTemplateTest.render(TotpRegister.PAGE, Map.of(TotpRegister.ATTRIBUTE, new TotpRegister.Refusal(key, "https://x.example.com/")));
        }
        String ftl = java.nio.file.Files.readString(java.nio.file.Path.of("src/main/resources/theme-resources/templates", TotpRegister.PAGE));
        assertFalse(ftl.contains("?no_esc"));
        assertFalse(ftl.contains("noautoesc"));
    }
}
