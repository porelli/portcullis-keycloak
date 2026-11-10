package eu.portcullis.signin;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Stand-ins for Keycloak's {@code CredentialEntity} and
 * {@code FederatedUserCredentialEntity} (same entity names, tables and id
 * column), so the store's JPQL runs against the test database unchanged.
 */
final class TestCredentials {
    private TestCredentials() {}

    @Entity(name = "CredentialEntity")
    @Table(name = "CREDENTIAL")
    public static class Local {
        @Id
        @Column(name = "ID", length = 36)
        protected String id;
    }

    @Entity(name = "FederatedUserCredentialEntity")
    @Table(name = "FED_USER_CREDENTIAL")
    public static class Federated {
        @Id
        @Column(name = "ID", length = 36)
        protected String id;
    }
}
