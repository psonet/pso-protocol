//! Error type returned by every fallible function in this crate.

use thiserror::Error;

/// Errors produced by `pso-protocol` formulas.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// The underlying Poseidon implementation failed to construct or hash.
    /// The string carries the upstream error verbatim — Poseidon errors
    /// are mostly configuration mistakes (bad arity, missing parameters)
    /// and we surface them as-is.
    #[error("poseidon error: {0}")]
    Poseidon(String),

    /// A byte input had the wrong length for the formula. Carries the
    /// expected length and the length we actually saw.
    #[error("invalid input length: expected {expected} bytes, got {actual}")]
    InvalidInputLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
}
