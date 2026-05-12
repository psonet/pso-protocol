# pso-protocol

[![CI](https://github.com/psonet/pso-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/psonet/pso-protocol/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/pso-protocol.svg)](https://crates.io/crates/pso-protocol)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Single source of truth** for every PSO consensus-binding hash formula
and witness type. Consumed in three places:

- **Rust wallets** (off-chain) — depend on `pso-protocol = "0.1"`.
- **PSO chain** (on-chain precompiles `0x0210..0x021F`) — depends on the
  same crate; each precompile body calls into `pso-protocol`.
- **Solidity contracts** — `forge install psonet/pso-protocol` and import
  `pso-protocol/PsoProtocol.sol`; the library is a thin set of
  `staticcall` wrappers around the precompiles.

The repo ships **both sides** so they version together. Cross-side
equality is checked in CI as a sanity backstop on top of the structural
guarantee that the precompiles call into the same Rust function as
off-chain consumers.

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
| `nft`        | On-chain precompiles `0x0211..0x0214`     | Yes (coordinated chain + wallet release). |
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
0x0211  PSO_PROTOCOL_TD_ID                 (this crate)
0x0212  PSO_PROTOCOL_TD_HASH               (this crate)
0x0213  PSO_PROTOCOL_SU_ID                 (this crate)
0x0214  PSO_PROTOCOL_SU_HASH               (this crate)
... 0x0215..0x021F reserved for future named formulas
```

`0x0202` (raw Poseidon) is kept for third-party L2 apps that need
Poseidon for their own non-PSO bindings without lobbying for a hardfork.
The pso-protocol precompiles are **additive, not replacement**.

Ownership is **not exposed as a precompile** — the chain never recomputes
it. The proof's public-input vector carries it.

## Usage

### Rust

```toml
[dependencies]
pso-protocol = "0.1"
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
`witness.rs`, and `merkle.rs` per the migration plan in
`pso-chain/docs/issues/pso-protocol-extraction.md`.

## no_std

v0.1 ships **std-only** because the underlying
[`pso-poseidon`](https://github.com/psonet/pso-poseidon) crate is not yet
no_std. The feature shape (`default = ["std"]`, every dep
`default-features = false`) is laid out for a future no_std story:
flipping `default = []` once `pso-poseidon` goes no_std will not change
the public API.

## License

[MIT](LICENSE) — same as `pso-vdf` and `pso-poseidon`.
