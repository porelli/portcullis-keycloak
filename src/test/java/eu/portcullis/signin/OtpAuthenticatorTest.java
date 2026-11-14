package eu.portcullis.signin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.models.AuthenticationExecutionModel;

/** portcullis-otp (contract §8.1 "Authenticator-app codes"): steps aside unless the code may be asked for. */
class OtpAuthenticatorTest {
    private static final SigninConfig ON = Configs.of(Configs.WITH_TOTP, false, "", "");

    private static OtpAuthenticator otp(SigninConfig cfg) {
        return new OtpAuthenticator(() -> cfg, (s, r) -> null);
    }

    /** alice, known in this authentication (a password step done), with one authenticator app. */
    private static Flow aliceWithCode() {
        Flow f = new Flow();
        Flow.Person alice = f.person("u-alice", "alice").otp("otp-1", "Authenticator 2026-11-14 10:00:00");
        f.user = alice.model;
        f.completed("pwd");
        return f;
    }

    private static Flow.Person person(Flow f) {
        return f.people().get(0);
    }

    private static void assertSteppedAside(Flow f, String why) {
        assertEquals(FlowStatus.ATTEMPTED, f.status, why);
        assertNull(f.page, why + ": no form");
        assertTrue(f.formAttributes.isEmpty(), why + ": the form untouched");
    }

    @Test
    void isNoCredentialValidator() {
        assertFalse(new OtpAuthenticator(Configs::plain) instanceof CredentialValidator);
        OtpAuthenticatorFactory factory = new OtpAuthenticatorFactory();
        assertEquals("portcullis-otp", factory.getId());
        assertEquals("otp", factory.getReferenceCategory());
        assertEquals("Authenticator app code (Portcullis)", factory.getDisplayType());
        assertEquals(List.of(AuthenticationExecutionModel.Requirement.ALTERNATIVE, AuthenticationExecutionModel.Requirement.DISABLED),
                List.of(factory.getRequirementChoices()));
        assertFalse(factory.isUserSetupAllowed());
        assertFalse(new OtpAuthenticator(Configs::plain).requiresUser());
        assertEquals("portcullis.otp.method", OtpAuthenticator.METHOD_NOTE);
        assertEquals("totp", OtpAuthenticator.TOTP);
        assertEquals("otp", OtpAuthenticator.OTP_TYPE);
    }

    @Test
    void offWhenSwitchedOff() {
        Flow f = aliceWithCode();
        otp(Configs.of(Configs.WITH_PASSWORD, false, "", "")).authenticate(f.context);
        assertSteppedAside(f, "totp off");
        Flow deny = aliceWithCode();
        otp(SigninConfig.DENY_ALL).authenticate(deny.context);
        assertSteppedAside(deny, "DENY_ALL");
        assertFalse(OtpAuthenticator.usable(person(f).model, Configs.of(Configs.WITH_PASSWORD, false, "", "")));
    }

    @Test
    void attemptedWithoutUser() {
        Flow f = new Flow();
        f.person("u-alice", "alice").otp("otp-1", "a");
        otp(ON).authenticate(f.context);
        assertSteppedAside(f, "nobody known: never a username field");
        f.form.add("otp", "123456");
        otp(ON).action(f.context);
        assertEquals(FlowStatus.ATTEMPTED, f.status, "a posted code without a user is never checked");
        assertTrue(f.people().get(0).checked.isEmpty());
    }

    @Test
    void attemptedWithoutCredential() {
        Flow f = new Flow();
        f.user = f.person("u-alice", "alice").passkey(PasskeyClassifier.TYPE_SYNCED, Flow.bytes("s")).model;
        otp(ON).authenticate(f.context);
        assertSteppedAside(f, "no otp credential");
        assertFalse(new OtpAuthenticator(() -> ON).configuredFor(f.session, f.realm, f.user));
    }

    @Test
    void attemptedForAdminAndHub() {
        for (String name : new String[] {"admin", "portcullis-hub", "Admin", " admin "}) {
            Flow f = new Flow();
            f.user = f.person("u-" + name.trim(), name).otp("otp-1", "a").model;
            otp(ON).authenticate(f.context);
            assertSteppedAside(f, name);
            assertFalse(OtpAuthenticator.usable(f.user, ON), name);
        }
    }

    @Test
    void attemptedWhenPcMethodOther() {
        Flow f = aliceWithCode();
        f.clientNotes.put(PcMethod.CLIENT_NOTE, "password");
        otp(ON).authenticate(f.context);
        assertSteppedAside(f, "pc_method=password");
        Flow passkey = aliceWithCode();
        passkey.authNotes.put(PcMethod.STEP_NOTE, "passkey");
        otp(ON).authenticate(passkey.context);
        assertSteppedAside(passkey, "a template step asking for a passkey");
        Flow asked = aliceWithCode();
        asked.clientNotes.put(PcMethod.CLIENT_NOTE, "totp");
        otp(ON).authenticate(asked.context);
        assertEquals(FlowStatus.CHALLENGE, asked.status, "pc_method=totp");
    }

    /** T13: an impersonated session never asks for the person's code. */
    @Test
    void attemptedWhenImpersonated() {
        Flow f = aliceWithCode();
        Imp.alice(f, person(f), "hwk");
        assertTrue(ImpersonationGuard.impersonated(f.session, f.realm, f.authSession).isPresent(), "the stand-in is impersonated");
        otp(ON).authenticate(f.context);
        assertSteppedAside(f, "impersonated");
        assertFalse(OtpAuthenticator.steps(f.context, ON));
        f.form.add("otp", "123456");
        otp(ON).action(f.context);
        assertEquals(FlowStatus.ATTEMPTED, f.status);
        assertTrue(person(f).checked.isEmpty(), "never checked");

        // The identity cookie's session impersonated: the same.
        Flow c = aliceWithCode();
        org.keycloak.models.UserSessionModel imp = Imp.session(new Flow(), person(c), "us-imp", Imp.notes(c, Imp.ID, Imp.NOW.plusSeconds(600), "hwk"));
        new OtpAuthenticator(() -> ON, (s, r) -> new org.keycloak.services.managers.AuthenticationManager.AuthResult(person(c).model, imp, null, null))
                .authenticate(c.context);
        assertSteppedAside(c, "impersonated identity cookie");
    }

    @Test
    void asksForTheCode() {
        Flow f = aliceWithCode();
        otp(ON).authenticate(f.context);
        assertEquals(FlowStatus.CHALLENGE, f.status);
        assertEquals("login-otp", f.page);
        assertTrue(OtpAuthenticator.steps(f.context, ON));
        assertTrue(new OtpAuthenticator(() -> ON).configuredFor(f.session, f.realm, f.user));
    }

    @Test
    void successWritesNote() {
        Flow f = aliceWithCode();
        person(f).otpValid = i -> "654321".equals(i.getChallengeResponse()) && "otp-1".equals(i.getCredentialId());
        f.form.add("otp", "654321");
        f.form.add("selectedCredentialId", "otp-1");
        otp(ON).action(f.context);
        assertEquals(FlowStatus.SUCCESS, f.status);
        assertEquals("totp", f.authNotes.get(OtpAuthenticator.METHOD_NOTE));
        assertTrue(f.eventErrors.isEmpty());
    }

    @Test
    void failureAddsHistory() {
        Flow f = aliceWithCode();
        f.headers.put("User-Agent", "Mozilla/5.0 (X11) Firefox/140.0");
        f.form.add("otp", "000000");
        f.form.add("selectedCredentialId", "otp-1");
        otp(ON).action(f.context);
        assertEquals(List.of("invalid_user_credentials"), f.eventErrors);
        Map<String, String> d = f.errorDetails.get(0);
        assertEquals("totp", d.get(History.METHOD));
        assertEquals("Mozilla/5.0 (X11) Firefox/140.0", d.get(History.UA));
        assertFalse(d.containsValue("000000"), "the code is never a detail");
        assertEquals(AuthenticationFlowError.INVALID_CREDENTIALS, f.error);
        assertTrue(f.countedByBruteForce(), "brute force counts a wrong code");
        assertNull(f.authNotes.get(OtpAuthenticator.METHOD_NOTE));
    }

    @Test
    void postedCodeAfterSwitchOffNeverChecked() {
        Flow f = aliceWithCode();
        person(f).otpValid = i -> true;
        f.form.add("otp", "654321");
        f.form.add("selectedCredentialId", "otp-1");
        otp(Configs.of(Configs.WITH_PASSWORD, false, "", "")).action(f.context);
        assertEquals(FlowStatus.ATTEMPTED, f.status);
        assertTrue(person(f).checked.isEmpty());
        assertNull(f.authNotes.get(OtpAuthenticator.METHOD_NOTE));
    }
}
