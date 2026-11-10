package eu.portcullis.signin;

import eu.portcullis.signin.store.PasskeyEntity;
import eu.portcullis.signin.store.PasskeyStoreProviderFactory;
import eu.portcullis.signin.store.SigninStateEntity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.Persistence;
import jakarta.persistence.PersistenceConfiguration;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;
import liquibase.command.CommandScope;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * An in-memory H2 with the extension's Liquibase changelog applied (plus the
 * two Keycloak credential tables the orphan sweep reads, reduced to their id),
 * and a Hibernate {@link EntityManager} over the extension's entities.
 */
final class TestDb implements AutoCloseable {
    private final String url = "jdbc:h2:mem:portcullis-" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1";
    private final Connection keepAlive;
    private final EntityManagerFactory emf;
    final EntityManager em;

    TestDb() throws Exception {
        keepAlive = DriverManager.getConnection(url, "sa", "");
        try (Statement s = keepAlive.createStatement()) {
            s.execute("CREATE TABLE CREDENTIAL (ID VARCHAR(36) PRIMARY KEY)");
            s.execute("CREATE TABLE FED_USER_CREDENTIAL (ID VARCHAR(36) PRIMARY KEY)");
        }
        try (Connection c = DriverManager.getConnection(url, "sa", "")) {
            Database db = DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(c));
            new CommandScope("update")
                    .addArgumentValue("changelogFile", PasskeyStoreProviderFactory.CHANGELOG)
                    .addArgumentValue("database", db)
                    .execute();
        }
        PersistenceConfiguration cfg = new PersistenceConfiguration("portcullis-test")
                .provider("org.hibernate.jpa.HibernatePersistenceProvider")
                .managedClass(PasskeyEntity.class)
                .managedClass(SigninStateEntity.class)
                .managedClass(TestCredentials.Local.class)
                .managedClass(TestCredentials.Federated.class)
                .property(PersistenceConfiguration.JDBC_URL, url)
                .property(PersistenceConfiguration.JDBC_USER, "sa")
                .property(PersistenceConfiguration.JDBC_PASSWORD, "")
                .property("hibernate.hbm2ddl.auto", "none");
        emf = Persistence.createEntityManagerFactory(cfg);
        em = emf.createEntityManager();
    }

    /** Runs f in a committed transaction (Keycloak's own, in production). */
    <T> T tx(Function<EntityManager, T> f) {
        em.getTransaction().begin();
        try {
            T out = f.apply(em);
            em.getTransaction().commit();
            return out;
        } catch (RuntimeException e) {
            em.getTransaction().rollback();
            throw e;
        }
    }

    void txRun(Consumer<EntityManager> f) {
        tx(e -> {
            f.accept(e);
            return null;
        });
    }

    void sql(String statement) throws Exception {
        try (Statement s = keepAlive.createStatement()) {
            s.execute(statement);
        }
    }

    @Override
    public void close() throws java.sql.SQLException {
        em.close();
        emf.close();
        try (Statement s = keepAlive.createStatement()) {
            s.execute("SHUTDOWN");
        }
        keepAlive.close();
    }

    // ── Minimal Keycloak models (only what the extension calls) ──

    static RealmModel realm(String id) {
        return (RealmModel) Proxy.newProxyInstance(TestDb.class.getClassLoader(), new Class<?>[] {RealmModel.class},
                (p, m, args) -> switch (m.getName()) {
                    case "getId", "getName" -> id;
                    case "hashCode" -> id.hashCode();
                    case "equals" -> p == args[0];
                    case "toString" -> "realm " + id;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }

    static UserModel user(String id, String username, String... groups) {
        List<GroupModel> gs = Stream.of(groups).map(TestDb::group).toList();
        return (UserModel) Proxy.newProxyInstance(TestDb.class.getClassLoader(), new Class<?>[] {UserModel.class},
                (p, m, args) -> switch (m.getName()) {
                    case "getId" -> id;
                    case "getUsername" -> username;
                    case "getGroupsStream" -> gs.stream();
                    case "hashCode" -> id.hashCode();
                    case "equals" -> p == args[0];
                    case "toString" -> "user " + username;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }

    static GroupModel group(String name) {
        return (GroupModel) Proxy.newProxyInstance(TestDb.class.getClassLoader(), new Class<?>[] {GroupModel.class},
                (p, m, args) -> switch (m.getName()) {
                    case "getName" -> name;
                    case "hashCode" -> name.hashCode();
                    case "equals" -> p == args[0];
                    case "toString" -> "group " + name;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
    }
}
