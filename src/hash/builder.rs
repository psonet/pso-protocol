//! Iterated `Poseidon2` builder.
//!
//! Every PSO entity hash and binding hash is structurally the same
//! computation: seed with `Fr::ZERO`, then for each input field element
//! do `state = Poseidon2(state, input)`. [`ProtocolHasher`] packages that
//! pattern into a fluent builder so each formula reads as a sequence of
//! `absorb*` calls and a single `finalize`.
//!
//! The builder API takes **primitives only** — `Fr`, `u64`, `u128`, and
//! slices thereof. Decoding from ABI types (`bytes32`, `uint256`, struct
//! references) lives in the integration crate's trait impls. This keeps
//! `pso-protocol` free of any ABI dependency.

use ark_bn254::Fr;
use pso_poseidon::PoseidonHasher;

use crate::ProtocolError;

/// Iterated Poseidon2 accumulator.
///
/// Construct with [`ProtocolHasher::new`], absorb inputs in order, then
/// call [`ProtocolHasher::finalize`] to get the final `Fr`. The builder
/// is consumed by every operation, which makes mis-ordering caught at
/// compile time — once you call `finalize`, you cannot accidentally
/// absorb more.
///
/// Errors from the underlying Poseidon implementation are deferred to
/// `finalize` (or to whichever absorb returns a `Result`). In practice
/// `Poseidon::<Fr>::new_circom(2)` only fails on configuration mistakes,
/// which is why most callers can `?`-propagate at the outer level.
#[derive(Clone, Debug)]
pub struct ProtocolHasher {
    /// Current accumulator state. Seeded to `Fr::ZERO` by `new`.
    state: Fr,
}

impl ProtocolHasher {
    /// Start a new hasher seeded with `Fr::ZERO`. The zero seed is part
    /// of the on-chain binding — do not change it.
    pub fn new() -> Self {
        Self {
            state: Fr::from(0u64),
        }
    }

    /// Absorb a single `Fr`.
    pub fn absorb(mut self, value: Fr) -> Result<Self, ProtocolError> {
        self.state = poseidon2(self.state, value)?;
        Ok(self)
    }

    /// Absorb a `u64` by widening to `Fr`.
    pub fn absorb_u64(self, value: u64) -> Result<Self, ProtocolError> {
        self.absorb(Fr::from(value))
    }

    /// Absorb a `u128` by widening to `Fr`.
    pub fn absorb_u128(self, value: u128) -> Result<Self, ProtocolError> {
        self.absorb(Fr::from(value))
    }

    /// Absorb a slice of `Fr` in order.
    pub fn absorb_many(mut self, values: &[Fr]) -> Result<Self, ProtocolError> {
        for v in values {
            self = self.absorb(*v)?;
        }
        Ok(self)
    }

    /// Finalize the accumulator and return the digest.
    pub fn finalize(self) -> Fr {
        self.state
    }
}

impl Default for ProtocolHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Pairwise Poseidon2 over BN254 Fr. The 2-input arity is the iterated
/// building block for `ProtocolHasher`. Exposed for cases where a caller
/// genuinely needs a one-shot pair hash without a builder.
pub fn poseidon2(a: Fr, b: Fr) -> Result<Fr, ProtocolError> {
    let mut poseidon = pso_poseidon::Poseidon::<Fr>::new_circom(2)
        .map_err(|e| ProtocolError::Poseidon(format!("new_circom(2): {e}")))?;
    poseidon
        .hash(&[a, b])
        .map_err(|e| ProtocolError::Poseidon(format!("hash: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_builder_returns_zero_seed() {
        let h = ProtocolHasher::new().finalize();
        assert_eq!(h, Fr::from(0u64));
    }

    #[test]
    fn single_absorb_equals_poseidon2_zero_input() {
        let v = Fr::from(42u64);
        let from_builder = ProtocolHasher::new().absorb(v).unwrap().finalize();
        let direct = poseidon2(Fr::from(0u64), v).unwrap();
        assert_eq!(from_builder, direct);
    }

    #[test]
    fn absorb_u64_matches_absorb_fr() {
        let a = ProtocolHasher::new().absorb_u64(7).unwrap().finalize();
        let b = ProtocolHasher::new()
            .absorb(Fr::from(7u64))
            .unwrap()
            .finalize();
        assert_eq!(a, b);
    }

    #[test]
    fn absorb_many_equals_iterated_absorb() {
        let xs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let chained = ProtocolHasher::new()
            .absorb(xs[0])
            .unwrap()
            .absorb(xs[1])
            .unwrap()
            .absorb(xs[2])
            .unwrap()
            .finalize();
        let slice = ProtocolHasher::new().absorb_many(&xs).unwrap().finalize();
        assert_eq!(chained, slice);
    }
}
