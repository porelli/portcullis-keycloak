package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.models.Constants;

class TemplateAuthenticatorTest {
    /** The check with a given client-certificate answer for this request. */
    private static TemplateAuthenticator check(SigninConfig cfg, boolean certificate) {
        return new TemplateAuthenticator(() -> cfg) {
            @Override
            protected boolean certificateIsTheirs(AuthenticationFlowContext context, org.keycloak.models.UserModel user) {
                return certificate;
            }
        };
    }

    private static Flow signedIn(String... amrs) {
        Flow f = new Flow();
        Flow.Person alice = f.person("u-alice", "alice")
                .passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s"))
                .passkey(PasskeyClassifier.TYPE_SECURITY_KEY, Flow.bytes("k"));
        f.user = alice.model;
        f.completed(amrs);
        return f;
    }

    @Test
    void unlistedClientPasses() {
        Flow f = signedIn("spk");
        f.clientId = "portcullis-forward-auth";
        check(Configs.client(Configs.DEFAULT_METHODS, false, Configs.STRONG), false).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
    }

    @Test
    void listedClientMetPasses() {
        Flow f = signedIn("hwk");
        check(Configs.client(Configs.DEFAULT_METHODS, false, Configs.STRONG), false).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
    }

    @Test
    void listedClientUnmetShowsNeedsStronger() {
        Flow f = new Flow();
        f.user = f.person("u-bob", "bob").passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s")).model;
        f.completed("spk");
        check(Configs.client(Configs.DEFAULT_METHODS, false, Configs.STRONG), false).authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        assertEquals(TemplateAuthenticator.PAGE, f.page);
        NeedsStronger page = (NeedsStronger) f.formAttributes.get(TemplateAuthenticator.ATTRIBUTE);
        assertEquals("Nextcloud", page.getApp());
        assertEquals(List.of("passkey_synced"), page.getSignedIn());
        assertEquals(2, page.getAlternatives().size());
        assertEquals(List.of("security_key"), page.getAlternatives().get(0).getMethods());
        assertTrue(page.getAlternatives().get(0).isNotSetUp());
        assertFalse(page.getAlternatives().get(1).isNotSetUp(), "a certificate is unknown to Keycloak");
        // add_stronger off: a security key is stronger than the synced session → ask your admin;
        // a certificate always → ask your admin.
        assertFalse(page.isSetUpSecurityKey());
        assertTrue(page.isAskAdmin());
        assertEquals("https://auth.example.com/realms/portcullis/account/account-security/signing-in", page.getAccountUrl());

        Flow on = new Flow(); // add_stronger on: the security key gets its set-up link
        on.user = on.person("u-bob", "bob").passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s")).model;
        on.completed("spk");
        check(Configs.client(Configs.DEFAULT_METHODS, true, Configs.STRONG), false).authenticate(on.context);
        assertTrue(((NeedsStronger) on.formAttributes.get(TemplateAuthenticator.ATTRIBUTE)).isSetUpSecurityKey());
    }

    @Test
    void deniesWhenConfigInvalid() {
        for (String client : new String[] {"nextcloud", "portcullis-forward-auth", "account-console"}) {
            Flow f = signedIn("hwk", "mtls");
            f.clientId = client;
            check(SigninConfig.DENY_ALL, true).authenticate(f.context);
            // An error page, nobody signs in, and brute-force protection counts nothing.
            assertEquals(FlowStatus.FORCE_CHALLENGE, f.status, client);
            assertEquals("error", f.page, client);
            assertEquals(List.of(TemplateAuthenticator.UNAVAILABLE), f.formErrors, client);
            assertFalse(f.countedByBruteForce(), client);
        }
    }

    /** What Keycloak's flow reset does before the listener runs: every note and the user gone. */
    private static void reset(Flow f) {
        assertEquals(FlowStatus.FLOW_RESET, f.status);
        assertNotNull(f.resetListener);
        f.authNotes.clear();
        f.userSessionNotes.clear();
        f.user = null;
        f.status = null;
        f.resetListener.run();
    }

    @Test
    void allTemplateMetStepByStep() {
        SigninConfig cfg = Configs.client(Configs.DEFAULT_METHODS, false, Configs.SYNCED_AND_KEY);
        Flow f = signedIn("spk");
        f.authNotes.put(PasskeyAuthenticator.KIND_NOTE, "passkey_synced");
        Object alice = f.user;
        String completed = f.userSessionNotes.get(Constants.AUTHENTICATORS_COMPLETED);
        check(cfg, false).authenticate(f.context);
        reset(f);
        // The flow runs again asking for the security key, as if pc_method named it.
        assertEquals(java.util.Optional.of("security_key"), PcMethod.requested(f.context));
        assertSame(alice, f.user, "the person is kept");
        assertEquals(completed, f.userSessionNotes.get(Constants.AUTHENTICATORS_COMPLETED), "the synced passkey still counts");
        assertEquals("passkey_synced", f.authNotes.get(PasskeyAuthenticator.KIND_NOTE));
        // The re-run signs in with the security key: met.
        f.completed("spk", "hwk");
        check(cfg, false).authenticate(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
    }

    @Test
    void stepFailsWhenTheAccountChanged() {
        SigninConfig cfg = Configs.client(Configs.DEFAULT_METHODS, false, Configs.YUBIKEY_AND_CERT);
        Flow f = signedIn("hwk");
        check(cfg, true).authenticate(f.context);
        reset(f);
        assertEquals("u-alice", f.authNotes.get(TemplateAuthenticator.USER_NOTE));
        // The re-run ends with someone else (their certificate): refused, nobody left set.
        f.user = f.person("u-mallory", "mallory").model;
        f.completed("hwk", "mtls");
        check(cfg, true).authenticate(f.context);
        assertEquals(FlowStatus.FAILED, f.status);
        assertEquals(AuthenticationFlowError.USER_CONFLICT, f.error);
        assertEquals(null, f.user);
    }

    @Test
    void brokerFlowNeverResets() {
        // The setup link's post-broker login: an unmet listed client shows the page, no re-run.
        SigninConfig cfg = Configs.client(Configs.DEFAULT_METHODS, false, Configs.SYNCED_AND_KEY);
        Flow f = signedIn("spk");
        f.authNotes.put(org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "{}");
        check(cfg, false).authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        assertEquals(TemplateAuthenticator.PAGE, f.page);
        assertEquals("none", f.clientNotes.get(FreshMapper.NOTE));

        Flow unlisted = signedIn("inv");
        unlisted.clientId = "portcullis-forward-auth";
        unlisted.authNotes.put(org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT, "{}");
        check(cfg, false).authenticate(unlisted.context);
        assertEquals(FlowStatus.SUCCESS, unlisted.status);
        assertEquals("none", unlisted.clientNotes.get(FreshMapper.NOTE), "a setup link sets no pc_fresh");
    }

    @Test
    void certificateStepOnlyWhenPresented() {
        SigninConfig cfg = Configs.client(Configs.DEFAULT_METHODS, false, Configs.YUBIKEY_AND_CERT);
        Flow f = signedIn("hwk");
        check(cfg, true).authenticate(f.context);
        reset(f);
        assertEquals(java.util.Optional.of("yubikey_cert"), PcMethod.requested(f.context));

        Flow none = signedIn("hwk");
        check(cfg, false).authenticate(none.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, none.status, "no certificate on this request: it can't be completed here");
    }

    @Test
    void unmeetableShowsThePage() {
        // Both methods of the only alternative missing: no candidate.
        Flow f = signedIn("spk");
        check(Configs.client(Configs.DEFAULT_METHODS, false, Configs.YUBIKEY_AND_CERT), true).authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
        assertEquals(TemplateAuthenticator.PAGE, f.page);
    }

    @Test
    void neverAsksTwice() {
        SigninConfig cfg = Configs.client(Configs.DEFAULT_METHODS, false, Configs.SYNCED_AND_KEY);
        Flow f = signedIn("spk");
        f.authNotes.put(TemplateAuthenticator.ASKED_NOTE, "security_key");
        check(cfg, false).authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);
    }

    @Test
    void candidatesFollowTheStepUpRule() {
        Rule standard = Configs.client(Configs.DEFAULT_METHODS, false, Configs.STANDARD).templateForClient("nextcloud").orElseThrow();
        // Nothing yet: every alternative lacks one method; only set-up kinds and completable methods.
        assertEquals(List.of("passkey_synced", "security_key"),
                TemplateAuthenticator.candidates(standard, Set.of(), Set.of("passkey_synced", "security_key"), m -> false));
        assertEquals(List.of("passkey_synced", "yubikey_cert"),
                TemplateAuthenticator.candidates(standard, Set.of(), Set.of("passkey_synced"), m -> m.equals("yubikey_cert")));
        Rule both = Configs.client(Configs.DEFAULT_METHODS, false, Configs.YUBIKEY_AND_CERT).templateForClient("nextcloud").orElseThrow();
        assertEquals(List.of(), TemplateAuthenticator.candidates(both, Set.of(), Set.of("security_key"), m -> true));
        assertEquals(List.of("security_key"), TemplateAuthenticator.candidates(both, Set.of("yubikey_cert"), Set.of("security_key"), m -> true));
    }

    @Test
    void passwordCandidateNeverForTheRefusedAccounts() {
        String basicish = "{\"op\": \"all\", \"items\": [\"security_key\", \"password\"]}";
        SigninConfig cfg = Configs.client(Configs.WITH_PASSWORD, false, basicish);
        Flow f = new Flow();
        f.user = f.person("u-admin", "admin").model;
        f.completed("hwk");
        check(cfg, false).authenticate(f.context);
        assertEquals(FlowStatus.FORCE_CHALLENGE, f.status);

        Flow alice = signedIn("hwk");
        check(cfg, false).authenticate(alice.context);
        reset(alice);
        assertEquals(java.util.Optional.of("password"), PcMethod.requested(alice.context));
    }
}
