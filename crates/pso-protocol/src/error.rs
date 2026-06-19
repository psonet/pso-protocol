//! Single error type for the generic protocol core.

use thiserror::Error;

/// Errors produced by suite primitives and protocol logic.
#[derive(Debug, Error)]
pub enum Error {
    /// A pluggable hash/KDF primitive failed.
    #[error("hash error: {0}")]
    Hash(String),

    /// A curve point that must be affine/non-identity was the identity.
    #[error("unexpected identity point: {0}")]
    Identity(&'static str),

    /// A signature failed to verify, or signing failed.
    #[error("signature error: {0}")]
    Signature(&'static str),

    /// Owner commitment did not match the value carried by the entity.
    #[error("owner mismatch: commit(pk, nonce) != entity.owner()")]
    OwnerMismatch,

    /// More real ownership witnesses than the requested aggregation tier holds.
    #[error("aggregation of {0} slots exceeds the requested tier")]
    TierOverflow(usize),

    /// Bytes meant to be a field element were not canonical: their value
    /// is >= the field modulus, so decoding them would silently reduce
    /// (alias) them onto a different element.
    #[error("non-canonical field encoding: {0}")]
    NonCanonical(&'static str),

    /// A ZK proof backend (generation or verification) failed.
    #[error("zk proof error: {0}")]
    Proof(String),

    /// A Merkle / inclusion-tree operation failed (bad depth, index overflow,
    /// malformed path).
    #[error("merkle error: {0}")]
    Merkle(String),
}
