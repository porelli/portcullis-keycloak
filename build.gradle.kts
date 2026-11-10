// The Portcullis sign-in extension for Keycloak 26.8.1 (contract §8.1).
// Everything Keycloak already ships is compileOnly at exactly the version
// Keycloak 26.8.1 ships (keycloak-parent 26.8.1 and its quarkus-bom 3.40.1):
// the jar carries only our own classes. The Keycloak artifacts are
// non-transitive, so the compile classpath (and verification-metadata.xml)
// holds just what the code uses. Every artifact is checked against
// gradle/verification-metadata.xml (sha256; --dependency-verification strict
// in the Dockerfile).
plugins {
    java
}

repositories {
    mavenCentral()
}

val keycloak = "26.8.1"
val webauthn4j = "0.30.3.RELEASE" // keycloak-parent 26.8.1 webauthn4j.version
val jackson = "2.21.7"            // quarkus-bom 3.40.1
val jacksonAnnotations = "2.21"   // quarkus-bom 3.40.1
val jbossLogging = "3.6.3.Final"  // quarkus-bom 3.40.1
val junit = "6.1.3"               // quarkus-bom 3.40.1
val jakartaPersistence = "3.2.0"  // quarkus-bom 3.40.1
val jakartaRs = "3.1.0"           // quarkus-bom 3.40.1
// Test-only: the store tests run the Liquibase changelog on an in-memory H2
// and map the entities with Hibernate, at the versions Keycloak 26.8.1 runs.
val hibernate = "7.4.9.Final"     // quarkus-bom 3.40.1
val liquibase = "4.33.0"          // quarkus-bom 3.40.1
val h2 = "2.4.240"                // quarkus-bom 3.40.1
// Test-only: the needs-stronger page rendered as Keycloak renders it.
val freemarker = "2.3.35"         // keycloak-parent 26.8.1 freemarker.version
// Test-only: Keycloak's X.509 authenticator links its CRL / OCSP loader (Apache HttpClient).
val httpclient = "4.5.14"         // quarkus-bom 3.40.1
val httpcore = "4.4.16"           // quarkus-bom 3.40.1

dependencies {
    for (a in listOf(
        "keycloak-server-spi",
        "keycloak-server-spi-private",
        "keycloak-services",
        "keycloak-model-jpa",
        "keycloak-model-storage-private",
        "keycloak-core",
        "keycloak-common",
    )) {
        compileOnly("org.keycloak:$a:$keycloak") { isTransitive = false }
    }
    compileOnly("com.webauthn4j:webauthn4j-core:$webauthn4j") { isTransitive = false }
    compileOnly("com.fasterxml.jackson.core:jackson-databind:$jackson") { isTransitive = false }
    compileOnly("com.fasterxml.jackson.core:jackson-core:$jackson") { isTransitive = false }
    compileOnly("com.fasterxml.jackson.core:jackson-annotations:$jacksonAnnotations") { isTransitive = false }
    compileOnly("org.jboss.logging:jboss-logging:$jbossLogging") { isTransitive = false }
    compileOnly("jakarta.persistence:jakarta.persistence-api:$jakartaPersistence") { isTransitive = false }
    compileOnly("jakarta.ws.rs:jakarta.ws.rs-api:$jakartaRs") { isTransitive = false }

    testImplementation(platform("org.junit:junit-bom:$junit"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("com.fasterxml.jackson.core:jackson-databind:$jackson")
    testImplementation("com.webauthn4j:webauthn4j-test:$webauthn4j")
    // The test attestation leaves' AAGUID extension (the version webauthn4j-test brings).
    testImplementation("org.bouncycastle:bcprov-jdk15to18:1.83")
    testRuntimeOnly("org.jboss.logging:jboss-logging:$jbossLogging")
    testImplementation("org.hibernate.orm:hibernate-core:$hibernate")
    testImplementation("org.liquibase:liquibase-core:$liquibase")
    testRuntimeOnly("com.h2database:h2:$h2")
    testImplementation("org.freemarker:freemarker:$freemarker")
    testRuntimeOnly("org.apache.httpcomponents:httpclient:$httpclient") { isTransitive = false }
    testRuntimeOnly("org.apache.httpcomponents:httpcore:$httpcore") { isTransitive = false }
    // Keycloak's JsonSerialization (credential data, completed executions) registers these.
    testRuntimeOnly("com.fasterxml.jackson.datatype:jackson-datatype-jdk8:$jackson")
    testRuntimeOnly("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:$jackson")
}

// The tests also see what the extension compiles against (Keycloak's SPI, as
// Keycloak ships it).
configurations.testImplementation { extendsFrom(configurations.compileOnly.get()) }

tasks.withType<JavaCompile>().configureEach {
    options.release = 21
    options.encoding = "UTF-8"
    // -classfile: Keycloak's ComponentModel (reached through the authenticator
    // and mapper SPI) carries Infinispan protostream annotations, which aren't
    // on the compile classpath; javac can only warn that it can't read them.
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-classfile", "-Werror"))
}

tasks.jar {
    archiveFileName = "portcullis-signin.jar"
    exclude("**/.gitkeep")
}

tasks.test {
    useJUnitPlatform()
    // Liquibase's anonymous usage reporting: never from a build.
    systemProperty("liquibase.analytics.enabled", "false")
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
