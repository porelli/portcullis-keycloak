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

dependencies {
    for (a in listOf(
        "keycloak-server-spi",
        "keycloak-server-spi-private",
        "keycloak-services",
        "keycloak-model-jpa",
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

    testImplementation(platform("org.junit:junit-bom:$junit"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("com.fasterxml.jackson.core:jackson-databind:$jackson")
    testImplementation("com.webauthn4j:webauthn4j-test:$webauthn4j")
    testRuntimeOnly("org.jboss.logging:jboss-logging:$jbossLogging")
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 21
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

tasks.jar {
    archiveFileName = "portcullis-signin.jar"
    exclude("**/.gitkeep")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
