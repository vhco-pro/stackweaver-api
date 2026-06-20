<div align="center">

<img src="https://sw.vhco.pro/logo.png" alt="Stackweaver" width="150" />

# Stackweaver API

[![Release](https://github.com/vhco-pro/stackweaver-api/actions/workflows/release.yml/badge.svg)](https://github.com/vhco-pro/stackweaver-api/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/vhco-pro/stackweaver-api?sort=semver)](https://github.com/vhco-pro/stackweaver-api/releases/latest)
[![CodeQL](https://github.com/vhco-pro/stackweaver-api/actions/workflows/codeql.yml/badge.svg)](https://github.com/vhco-pro/stackweaver-api/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/vhco-pro/stackweaver-api/badge)](https://scorecard.dev/viewer/?uri=github.com/vhco-pro/stackweaver-api)
[![License](https://img.shields.io/badge/license-BSL%201.1-blue)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-sw.vhco.pro-0ea5e9)](https://sw.vhco.pro/docs)

The Go backend for the [Stackweaver](https://sw.vhco.pro) DevOps platform.

</div>

This is the public release repository for the Stackweaver API. It is published from the Stackweaver source tree on every release. See the [release sync architecture](https://sw.vhco.pro/docs/security/sync-architecture) for how releases are built, signed, and mirrored here.

## Usage

```bash
docker pull ghcr.io/vhco-pro/stackweaver-api:latest
```

See the [Stackweaver documentation](https://sw.vhco.pro/docs) for deployment instructions.


## Verifying this Distribution

Every image published by this satellite is Sigstore-signed (keyless, via Fulcio + Rekor) and ships with build-provenance and SBOM attestations. To verify a specific tag:

```bash
cosign verify \
  --certificate-identity-regexp "^https://github\.com/vhco-pro/stackweaver-api/\.github/workflows/release\.yml@refs/tags/.+$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/vhco-pro/stackweaver-api:<tag>
```

The full verification guide including SBOM extraction, SLSA provenance (live after the Wave-6 visibility flip), and `gitsign verify` for sync commits lives at <https://sw.vhco.pro/docs/security/verifying-releases>.

## Trademark

Stackweaver™ is a trademark of VH & Co. The Stackweaver name and word mark identify the official Stackweaver project; the source-code licence does not grant a right to use the mark in product names, hosted services, or company names. See the [Trademark Policy](https://github.com/vhco-pro/.github/blob/main/TRADEMARK.md) for the full terms.

## License

Business Source License 1.1 — see [LICENSE](LICENSE) for details.
