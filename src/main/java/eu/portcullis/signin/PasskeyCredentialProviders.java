package eu.portcullis.signin;

import com.webauthn4j.converter.util.ObjectConverter;
import eu.portcullis.signin.store.PasskeyStore;
import org.keycloak.authentication.authenticators.browser.WebAuthnMetadataService;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProvider;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * The WebAuthn credential providers of the two stronger passkey kinds
 * (contract §8.1 provider ids {@code portcullis-security-key},
 * {@code portcullis-device-passkey}): the stock passwordless provider with its
 * own credential type (the provider id) and account-console metadata. Synced
 * passkeys stay with the stock {@code keycloak-webauthn-passwordless}
 * provider and type {@code webauthn-passwordless}.
 */
public final class PasskeyCredentialProviders {
    private PasskeyCredentialProviders() {}

    /** A passwordless WebAuthn provider of one Portcullis credential type. */
    public static final class Provider extends WebAuthnPasswordlessCredentialProvider {
        private final String type;
        private final String displayName;
        private final String helpText;

        Provider(KeycloakSession session, WebAuthnMetadataService metadata, ObjectConverter objects,
                String type, String displayName, String helpText) {
            super(session, metadata, objects);
            this.type = type;
            this.displayName = displayName;
            this.helpText = helpText;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
            return CredentialTypeMetadata.builder()
                    .type(type)
                    .category(CredentialTypeMetadata.Category.PASSWORDLESS)
                    .displayName(displayName)
                    .helpText(helpText)
                    .iconCssClass("kcAuthenticatorWebAuthnPasswordlessClass")
                    .createAction(WebAuthnPasswordlessRegisterFactory.PROVIDER_ID)
                    .removeable(true)
                    .build(getKeycloakSession());
        }

        /** The credential and its attestation row go together. */
        @Override
        public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
            boolean removed = super.deleteCredential(realm, user, credentialId);
            if (removed) {
                PasskeyStore.of(getKeycloakSession()).remove(credentialId);
            }
            return removed;
        }
    }

    /** {@code portcullis-security-key}: a security key passkey (YubiKey touch). */
    public static final class SecurityKeyFactory extends WebAuthnPasswordlessCredentialProviderFactory {
        public static final String PROVIDER_ID = PasskeyClassifier.TYPE_SECURITY_KEY;

        @Override
        public Provider create(KeycloakSession session) {
            return new Provider(session, getMetadataService(), createOrGetObjectConverter(), PROVIDER_ID,
                    "Security key passkey", "Sign in by touching your security key (YubiKey).");
        }

        @Override
        public String getId() {
            return PROVIDER_ID;
        }
    }

    /** {@code portcullis-device-passkey}: a device-bound passkey. */
    public static final class DevicePasskeyFactory extends WebAuthnPasswordlessCredentialProviderFactory {
        public static final String PROVIDER_ID = PasskeyClassifier.TYPE_DEVICE;

        @Override
        public Provider create(KeycloakSession session) {
            return new Provider(session, getMetadataService(), createOrGetObjectConverter(), PROVIDER_ID,
                    "Device-bound passkey", "Sign in with a passkey kept on this device only.");
        }

        @Override
        public String getId() {
            return PROVIDER_ID;
        }
    }

    /** The provider id that stores a kind's credentials. */
    static String providerIdOf(String kind) {
        return switch (kind) {
            case PasskeyClassifier.SECURITY_KEY -> SecurityKeyFactory.PROVIDER_ID;
            case PasskeyClassifier.DEVICE -> DevicePasskeyFactory.PROVIDER_ID;
            default -> WebAuthnPasswordlessCredentialProviderFactory.PROVIDER_ID;
        };
    }
}
