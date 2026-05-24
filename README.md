# Stackweaver API

The Go backend for the [Stackweaver](https://github.com/vhco-pro/stackweaver) DevOps platform.

> [!IMPORTANT]
> **This repository is auto-synced from the Stackweaver monorepo. Changes to the `backend` directory will be overwritten.**

## Usage

```bash
docker pull ghcr.io/vhco-pro/stackweaver-api:latest
```

See the [Stackweaver documentation](https://github.com/vhco-pro/stackweaver) for deployment instructions.


## Verifying this Distribution

Every image published by this satellite is Sigstore-signed (keyless, via Fulcio + Rekor) and ships with build-provenance and SBOM attestations. To verify a specific tag:

```bash
cosign verify \
  --certificate-identity-regexp "^https://github\.com/vhco-pro/stackweaver-api/\.github/workflows/release\.yml@refs/tags/.+$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/vhco-pro/stackweaver-api:<tag>
```

The full verification guide — including SLSA provenance, SBOM extraction, and `gitsign verify` for sync commits — lives at <https://sw.vhco.pro/docs/security/verifying-releases>.

## License

Business Source License 1.1 — see [LICENSE](LICENSE) for details.
