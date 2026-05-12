//! # pso-protocol
//!
//! Consensus-binding primitives for the PSO protocol. Owns the **single
//! source of truth** for every hash formula and witness type that has to
//! agree byte-for-byte across:
//!
//! - Wallets (Rust off-chain).
//! - The PSO chain (Rust on-chain precompiles at `0x0210..0x021F`).
//! - Solidity contracts (via the `solidity/PsoProtocol.sol` library which
//!   wraps the precompiles as `staticcall`s).
//!
//! ## Binding policy
//!
//! Each module documents what it binds to and the upgrade cost of a change:
//!
//! | Module       | Binds to                                  | Hardfork required? |
//! | ------------ | ----------------------------------------- | ------------------ |
//! | `hash`       | Internal building block (Poseidon2 / Poseidon4 / Poseidon5). Not directly bound. | N/A — changing these would break everything below. |
//! | `binding`    | On-chain precompile `0x0210`.             | Yes — coordinated chain + wallet release. |
//! | `nft`        | On-chain precompiles `0x0211` (TD hash) and `0x0212` (SU hash). The id formulas (`compute_tribute_draft_id`, no SU-id) stay in this crate for wallet use but have no on-chain precompile — TD-id's `owner` input bakes in off-chain nonce randomness and SU ids are random, so on-chain recomputation gains nothing the ZK proof doesn't already attest. | Yes — coordinated chain + wallet release. |
//! | `ownership`  | The ZK circuit (Noir source).             | Yes — new ACIR → new canonical descriptor. Not exposed in Solidity. |
//! | `merkle`     | The ZK circuit Merkle-path semantics.     | Yes — coordinated circuit release. |
//! | `witness`    | The ZK circuit public-input layout.       | Yes — coordinated circuit + wallet release. |
//!
//! **Any change to a published function's output bytes is a major-version
//! bump.** See `README.md` for the coordinated-upgrade policy.

#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use)]

pub mod binding;
pub mod error;
pub mod fr;
pub mod hash;
pub mod merkle;
pub mod nft;
pub mod ownership;
pub mod witness;

pub use error::ProtocolError;

/// Re-export the BN254 scalar field so consumers don't have to depend on
/// `ark-bn254` directly just to spell the `Fr` type.
pub use ark_bn254::Fr;
