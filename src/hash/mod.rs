//! Poseidon-based hash primitives.
//!
//! Two distinct patterns coexist intentionally — they have different
//! binding partners and so different upgrade processes:
//!
//! - [`builder::ProtocolHasher`] — iterated `Poseidon2` over a stream of
//!   `Fr` values. Used by all entity hashes (`nft.rs`) and the binding
//!   hash (`binding.rs`). Bound to on-chain precompiles.
//!
//! - [`poseidon5::poseidon5`] — single-shot `Poseidon5` over five `Fr`
//!   values. Used only by the ownership formula (`ownership.rs`). Bound
//!   to the ZK circuit; not exposed as a precompile because the chain
//!   never recomputes ownership.
//!
//! Do not try to unify these. They are documented to be different.

pub mod builder;
pub mod poseidon5;

pub use builder::ProtocolHasher;
pub use poseidon5::poseidon5;
