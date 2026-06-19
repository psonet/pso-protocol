# pso-protocol

[![crates.io](https://img.shields.io/crates/v/pso-protocol.svg)](https://crates.io/crates/pso-protocol)
[![release](https://img.shields.io/github/v/release/psonet/pso-protocol.svg)](https://github.com/psonet/pso-protocol/releases)
[![CI](https://github.com/psonet/pso-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/psonet/pso-protocol/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The PSO consensus-binding protocol logic, written once against a swappable
cryptographic `Suite`. A Cargo workspace of two crates that always ship at the
same version:

- **[`pso-protocol`](crates/pso-protocol)** — the generic, Suite-based protocol
  core: entity/owner/binding/payload hash formulas, the ownership-proof
  statement, and witness/public-input semantics. Production suite `PsoV1`
  (BN254 / Grumpkin, Poseidon2, Grumpkin Schnorr). See its
  [README](crates/pso-protocol/README.md) for the architecture and usage.
- **[`pso-protocol-derive`](crates/pso-protocol-derive)** — the
  `#[derive(Entity)]` macro that maps a typed (e.g. Solidity-mirroring) struct's
  named fields to the canonical entity preimage.

```toml
[dependencies]
pso-protocol = "0.8"
pso-protocol-derive = "0.8"   # only if you derive `Entity`
```

## Verifying releases

Releases ship sigstore cosign signatures + SLSA build-provenance attestations for every published `.crate`. See [SECURITY.md](SECURITY.md) for the threat model and the copy-pasteable verify recipe.

Quick check:

```sh
TAG=v0.8.0
ARTIFACT=pso-protocol-${TAG#v}.crate
gh release download "$TAG" --repo psonet/pso-protocol \
  --pattern "$ARTIFACT" --pattern "$ARTIFACT.sig" --pattern "$ARTIFACT.pem"
cosign verify-blob \
  --certificate "$ARTIFACT.pem" --signature "$ARTIFACT.sig" \
  --certificate-identity-regexp \
    '^https://github\.com/psonet/pso-protocol/\.github/workflows/ci\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ARTIFACT"
```

## License

[MIT](LICENSE) — same as `pso-vdf` and `pso-poseidon`.
