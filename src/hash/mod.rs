//! Poseidon-based hash primitives.
//!
//! Four distinct patterns coexist intentionally -- they have different
//! binding partners and so different upgrade processes:
//!
//! - [`builder::ProtocolHasher`] -- iterated `Poseidon2` over a seed and
//!   a stream of `Fr` values. Used by entity hashes (`nft.rs`). Bound
//!   to on-chain precompiles `0x0211`, `0x0212`.
//!
//! - [`poseidon3::poseidon3`] -- single-shot `Poseidon3` over three `Fr`
//!   values. Used by the Grumpkin ownership formula (`ownership.rs`).
//!   Bound to the ZK circuit; not exposed as a precompile.
//!
//! - [`poseidon4::poseidon4`] -- single-shot `Poseidon4` over four `Fr`
//!   values. Used by the binding hash (`binding.rs`). Bound to on-chain
//!   precompile `0x0210`.
//!
//! - [`poseidon5::poseidon5`] -- single-shot `Poseidon5` over five `Fr`
//!   values. Kept for backward compatibility with the pre-Grumpkin
//!   ownership formula and any callers that still reference it. The
//!   current ownership commitment uses `poseidon3`.
//!
//! Do not try to unify these. They are documented to be different.

pub mod builder;
pub mod poseidon3;
pub mod poseidon4;
pub mod poseidon5;

pub use builder::{poseidon2, ProtocolHasher};
pub use poseidon3::poseidon3;
pub use poseidon4::poseidon4;
pub use poseidon5::poseidon5;
