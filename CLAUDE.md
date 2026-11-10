# Portcullis Keycloak — Claude Code Instructions

## Project Overview

The Portcullis sign-in extension for Keycloak 26.8.1, published as `ghcr.io/porelli/portcullis-keycloak` (the official Keycloak image pinned `tag@sha256` plus `portcullis-signin.jar` in `/opt/keycloak/providers/`). It reads the Hub's `signin-keycloak.json` (core mounts `hub_data:/hub-data:ro`) and enforces sign-in methods and templates inside Keycloak. The cross-repo interfaces are defined in `portcullis-docs/docs/guides/integration-contracts.md` (§1, §8, §8.1) — change that page first.

## Layout

| Path | Purpose |
|------|---------|
| `src/main/java/eu/portcullis/signin/SigninConfig.java` | `/hub-data/signin-keycloak.json` (contract §8.1, plan D20): `current()` (cached by mtime + size + file key, re-read when any changes), `load(Path)` (strict Jackson: unknown fields, trailing data, duplicate keys, a missing field, `null`, a coerced scalar, another `version` or any value outside its rule refuse the whole file → `DENY_ALL`, logged without the file's content), `DENY_ALL` (every method off, every client's template unmeetable, no authenticators, `mdsSerial()` -1), `on(method)` (`browser_cert` never), `addStronger()`, `mdsSerial()`, `templateForClient(clientId)` (unlisted → empty; with `DENY_ALL` every client gets `Rule.UNMEETABLE`), `clientName`, `authenticator(aaguid)` → `Trust(kind, status, roots)` |
| `src/main/java/eu/portcullis/signin/Rule.java` | Compiled rules: `parse(JsonNode)` (a group at the top, `op` all/any, exactly the keys `op` + `items`, 1–8 items, depth ≤ 4, ≤ 48 leaves, leaves the six method ids only — no families, no `inv`; else `IllegalArgumentException`), `satisfiedBy(methods)`, `alternatives()` (the minimal any-of-all-of form, as the Hub's `signin.Alternatives`) |
| `src/main/java/eu/portcullis/signin/Methods.java` | The method table (D1): `forAmr(amr)` (`inv` and unknown values → empty), `tenths(method)`, `ofSession(session, realm, userSession)` (the stock amr — `AmrUtils` over the user session's completed executions — mapped through `forAmr`, kept only while `SigninConfig.current().on(m)`) |
| `src/main/resources/META-INF/services/` | SPI registrations (the provider ids below, as they land) |
| `src/test/resources/signin_vectors.json` | Byte copy of portcullis-hub `internal/signin/testdata/vectors.json`; `RuleTest.sharedVectors` runs every case; CI's `vectors` job `cmp`s it with the Hub's same-named branch, else main |
| `Dockerfile` | `base` (pinned `gradle:<ver>-jdk21@sha256`, `$BUILDPLATFORM`), `build` (`gradle jar`), `test` (`gradle test`), final = pinned Keycloak + the jar |
| `gradle/verification-metadata.xml` | sha256 of every artifact (Gradle dependency verification, `--dependency-verification strict`) |
| `.github/workflows/build.yml` | `test` (`docker buildx build --target test .` + the auto-merge tests), `vectors`, `smoke` (contents: read; smoke run: `start-dev`, `GET /admin/serverinfo` lists every id of `PROVIDER_IDS`; the multi-platform build), `publish` (only job with `packages: write` / `id-token: write`; `edge` on main, semver on `v*`, cosign); the test job also checks the Dockerfile's Keycloak tag equals `val keycloak` in `build.gradle.kts` |
| `.github/automerge/`, `.github/workflows/dependabot-automerge.yml` | Dependabot auto-merge, the same files as the other repos (keep `automerge.sh` byte-identical to the Hub's) |

## Commands

```bash
./gradlew test jar                                   # local (JDK 21)
docker build --target test . && docker build .       # what CI runs
./gradlew --write-verification-metadata sha256 test jar   # after any dependency change; review the diff
```

## Critical Rules

- **Contract first.** `integration-contracts.md` §8.1 is the source of truth for `signin-keycloak.json`, the methods, rules, `pc_method`, `pc_fresh` and the provider ids; change it before the code. The rule evaluation must give the Hub's results (`internal/signin`): the shared vectors are the check.
- **Fail closed.** A missing, unreadable or invalid `signin-keycloak.json` is `DENY_ALL`: nobody signs in. An unknown method, rule shape or file version denies; a method that is off is never accepted.
- **Secrets** never on argv or in logs (the CI smoke run's admin password comes from the environment and a 0600 file).
- **Supply chain.** Every image `tag@sha256`; every action pinned by full commit SHA with a `# vX.Y.Z` comment; Gradle wrapper with `distributionSha256Sum`; `verification-metadata.xml` with sha256 for every artifact. Keycloak's own SPI and the libraries it ships (webauthn4j, Jackson, jboss-logging) are `compileOnly`, non-transitive, at exactly the versions Keycloak 26.8.1 ships (keycloak-parent / quarkus-bom); a Keycloak bump moves the base image and these together, by hand (CI fails when the Dockerfile's Keycloak tag and `val keycloak` differ; Dependabot ignores these artifacts, the JUnit BOM and Keycloak minor/major image updates). Dependabot (gradle, docker, github-actions) doesn't regenerate `verification-metadata.xml`: a Gradle bump needs it regenerated and pushed to the PR.
- **Prefer mature libraries**: Keycloak's SPI, webauthn4j (attestation parsing, cert-path validation), Jackson, the JDK's `CertificateFactory`; no hand-rolled X.509 or CBOR code.
- **No migration code**: there are no installs to upgrade from.
- **Provider ids** (plan D5, contract §8.1): `webauthn-register-passwordless` (overrides the stock required action), `portcullis-security-key`, `portcullis-device-passkey`, `portcullis-passkey-store`, `portcullis-reclassify`, `portcullis-passkey`, `portcullis-condition-passkey-kind`, `portcullis-method`, `portcullis-password-form`, `portcullis-x509`, `portcullis-fresh`, `auth-cookie` (overrides the stock provider), `portcullis-template`. Add each to `build.yml` `PROVIDER_IDS` when it lands.

## Related Repos

| Repo | Purpose |
|------|---------|
| `porelli/portcullis` | Core stack (Traefik, Keycloak, LLDAP, group-gate, CLI); runs this image (`KEYCLOAK_IMAGE`) |
| `porelli/portcullis-hub` | Writes `signin-keycloak.json`; owns the shared rule vectors |
| `porelli/portcullis-docs` | Documentation site, incl. the integration contracts |
