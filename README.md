# Portcullis Keycloak

The Keycloak extension of [Portcullis](https://github.com/porelli/portcullis) — the self-hosted YubiKey authentication gateway. It adds sign-in methods and templates to Keycloak: which passkey kind signed in, per-client sign-in templates, and passkey kinds decided from the authenticator's attestation and the FIDO metadata list.

**Documentation: <https://porelli.github.io/portcullis-docs/>** — sign-in methods and the extension are covered in [Integration Contracts](https://porelli.github.io/portcullis-docs/guides/integration-contracts/) (§8.1).

## Docker Image

Images are published to `ghcr.io/porelli/portcullis-keycloak`: the official Keycloak image, pinned by digest, plus the extension's jar in `/opt/keycloak/providers/`.

| Tag | When |
|-----|------|
| `X.Y.Z`, `X.Y`, `X`, `sha-<short>` | release tags `vX.Y.Z` |
| `edge` | every push to `main` |

There is no `latest` tag. Pin a release by tag and digest. Every pushed image has SBOM and provenance attestations and is signed with cosign (keyless, GitHub OIDC). To verify:

```bash
cosign verify ghcr.io/porelli/portcullis-keycloak:1.0.0 \
  --certificate-identity-regexp '^https://github.com/porelli/portcullis-keycloak/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The core Portcullis stack runs it (`KEYCLOAK_IMAGE`); you don't need to run it standalone.

## Development

```bash
./gradlew test                 # JDK 21
docker build --target test .   # the same tests, as CI runs them
docker build .                 # the image
```

See `CLAUDE.md` for the layout and the rules.

## License

MIT
