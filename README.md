# pso-protocol

[![crates.io](https://img.shields.io/crates/v/pso-protocol.svg)](https://crates.io/crates/pso-protocol)
[![release](https://img.shields.io/github/v/release/psonet/pso-protocol.svg)](https://github.com/psonet/pso-protocol/releases)
[![CI](https://github.com/psonet/pso-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/psonet/pso-protocol/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Single source of truth** for every PSO consensus-binding hash formula
and witness type. Consumed in three places:

- **Rust wallets** (off-chain) — depend on `pso-protocol = "0.2"`.
- **PSO chain** (on-chain precompiles `0x0210..0x021F`) — depends on the
  same crate; each precompile body calls into `pso-protocol`.
- **Solidity contracts** — `forge install psonet/pso-protocol` and import
  `pso-protocol/PsoProtocol.sol`; the library is a thin set of
  `staticcall` wrappers around the precompiles.

The repo ships **both sides** so they version together. Cross-side
equality is checked in CI as a sanity backstop on top of the structural
guarantee that the precompiles call into the same Rust function as
off-chain consumers.

## Related repos

One of four sibling repos in the post-extraction layout:

- **`pso-protocol`** *(this repo)* — consensus-binding primitives.
- [`pso-zk-circuits`](https://github.com/psonet/pso-zk-circuits) — Noir circuits + FFI prover.
- `pso-integration` (internal) — client-side integration:
  UniFFI wallet bindings, SRA registrar, CLI, VDF FFI (planned), and
  the L2-interaction surface clients use to talk to the chain.
- `pso-chain` (internal) — PSO L2 chain (registers this crate's
  precompiles, links `PsoProtocol.sol` into its contracts).

## Why this crate exists

Before extraction, the same Poseidon-based formulas were reimplemented
in three places per entity — Rust mobile, Rust CLI, and Solidity. There
was no machine check preventing one from drifting. The binding hash had
three hand-written copies that had to stay byte-identical for proof
verification to work.

This crate eliminates the duplication by hosting the formulas exactly
once. Drift becomes structurally impossible.

## Binding policy

The crate organizes formulas by what they bind to. Each binding has a
different upgrade cost — knowing which file you're touching tells you
the release process you have to coordinate.

| Module       | Binds to                                  | Hardfork required to change? |
| ------------ | ----------------------------------------- | ---------------------------- |
| `hash`       | Internal Poseidon building blocks         | N/A — changing these breaks everything below. |
| `binding`    | On-chain precompile `0x0210`              | Yes (coordinated chain + wallet release). |
| `nft`        | On-chain precompiles `0x0211`, `0x0212`   | Yes (coordinated chain + wallet release). |
| `ownership`  | The ZK circuit (Noir source)              | Yes — new ACIR → new canonical descriptor. Not exposed in Solidity. |
| `witness`    | The ZK circuit public-input layout        | Yes (coordinated circuit + wallet release). |
| `merkle`     | The ZK circuit Merkle-path semantics      | Yes (coordinated circuit release). |

**Any change to a published function's output bytes is a major-version
bump** (semver-major). Such a change requires:

1. A new release of `pso-protocol`.
2. A coordinated `pso-chain` release that bumps the precompile bodies.
3. A coordinated `pso-integration` release that picks up the new
   formulas in wallets.
4. An on-chain hardfork that activates the new precompile at the same
   block height across the network.

The two Poseidon patterns the crate exposes — iterated Poseidon2 for
entity hashes (`hash::ProtocolHasher`) and single-shot Poseidon5 for
ownership (`hash::poseidon5`) — coexist intentionally. They bind to
different consumers (precompiles vs the ZK circuit) and so have
different upgrade processes. **Do not try to unify them.**

## Precompile allocation

```
0x0201  ZK_VERIFY                          (existing — pso-chain)
0x0202  POSEIDON (raw)                     (existing — pso-chain)
0x0203  CIRCUIT_INFO                       (existing — pso-chain)

0x0210  PSO_PROTOCOL_BINDING_HASH          (this crate)
0x0211  PSO_PROTOCOL_TD_HASH               (this crate)
0x0212  PSO_PROTOCOL_SU_HASH               (this crate)
... 0x0213..0x021F reserved for future named formulas
```

`0x0202` (raw Poseidon) is kept for third-party L2 apps that need
Poseidon for their own non-PSO bindings without lobbying for a hardfork.
The pso-protocol precompiles are **additive, not replacement**.

Ownership is **not exposed as a precompile** — the chain never recomputes
it. The proof's public-input vector carries it.

**TD-id and SU-id likewise have no precompile.** TD-id's formula
(`Poseidon2(owner, wwd)`) consumes an `owner` that already bakes in
off-chain nonce randomness, and SU ids are random by construction —
in both cases the ZK proof is the only legitimate witness, so
on-chain recomputation adds nothing. The Rust `compute_tribute_draft_id`
function stays in this crate for wallet use at mint time.

## Usage

### Rust

```toml
[dependencies]
pso-protocol = "0.2"
```

```rust
use pso_protocol::hash::ProtocolHasher;
use pso_protocol::Fr;

let digest = ProtocolHasher::new()
    .absorb(Fr::from(1u64))?
    .absorb_u64(42)?
    .finalize();
```

### Solidity

```bash
forge install psonet/pso-protocol
```

```solidity
import {PsoProtocol} from "pso-protocol/PsoProtocol.sol";

bytes32 h = PsoProtocol.computeBindingHash(msg.sender, tdId, block.chainid);
```

The library is `internal`-only — every call is inlined at compile time;
no separate deployment and no cross-contract call gas.

## Repo layout

```
pso-protocol/
├── Cargo.toml                  # Rust crate, published to crates.io
├── foundry.toml                # `forge install`-able Solidity package
├── remappings.txt
├── src/                        # Rust implementations
│   ├── lib.rs
│   ├── error.rs
│   ├── fr.rs                   # Fr ↔ bytes helpers
│   └── hash/
│       ├── mod.rs
│       ├── builder.rs          # ProtocolHasher (iterated Poseidon2)
│       └── poseidon5.rs        # Single-shot Poseidon5 (ownership only)
├── solidity/
│   ├── PsoProtocol.sol         # Thin staticcall wrappers
│   └── PsoProtocol.t.sol       # forge unit tests
├── tests/
│   └── cross_side_equality.rs  # Rust ↔ Solidity byte equality (revm host)
├── .github/workflows/ci.yml
├── README.md
└── LICENSE
```

Future phases will add `binding.rs`, `nft.rs`, `ownership.rs`,
`witness.rs`, and `merkle.rs` per the internal migration plan.

## no_std

Currently ships **std-only** because the underlying
[`pso-poseidon`](https://github.com/psonet/pso-poseidon) crate is not yet
no_std. The feature shape (`default = ["std"]`, every dep
`default-features = false`) is laid out for a future no_std story:
flipping `default = []` once `pso-poseidon` goes no_std will not change
the public API.

## Verifying releases

Releases tagged from `v0.2.3` onward ship sigstore cosign signatures + SLSA build-provenance attestations for every artifact. See [SECURITY.md](SECURITY.md) for the threat model and the copy-pasteable verify recipe.

Quick check:

```sh
TAG=v0.2.3
ARTIFACT=pso-protocol-${TAG#v}.crate
gh release download "$TAG" --repo psonet/pso-protocol \
  --pattern "$ARTIFACT" --pattern "$ARTIFACT.sig" --pattern "$ARTIFACT.pem"
cosign verify-blob \
  --certificate "$ARTIFACT.pem" --signature "$ARTIFACT.sig" \
  --certificate-identity-regexp \
    '^https://github\.com/psonet/pso-protocol/\.github/workflows/ci\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ARTIFACT"
```

## License

[MIT](LICENSE) — same as `pso-vdf` and `pso-poseidon`.
