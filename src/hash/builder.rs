//! Iterated `Poseidon2` builder.
//!
//! Every PSO entity hash is structurally the same computation: take the
//! first two inputs and Poseidon2-hash them, then for each subsequent
//! input chain `state = Poseidon2(state, next)`. [`ProtocolHasher`]
//! packages that pattern into a fluent builder so each formula reads as
//! a sequence of `absorb*` calls on a seed.
//!
//! The seed is **not** `Fr::ZERO`. The TD-id formula
//! `Poseidon2(owner, worldwide_day)` has no implicit zero — it hashes
//! exactly two inputs. The builder reflects that by requiring a seed at
//! construction: `ProtocolHasher::new(owner).absorb(wwd).finalize()`
//! produces `Poseidon2(owner, wwd)` byte-for-byte.
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
/// Constructed with a seed `Fr`. Each `absorb*` call computes
/// `state = Poseidon2(state, input)`. [`ProtocolHasher::finalize`]
/// returns the current accumulator.
///
/// The builder consumes itself on every operation, so once you call
/// `finalize` you cannot accidentally absorb more.
///
/// Errors from the underlying Poseidon implementation are surfaced at
/// each `absorb*` site. In practice `Poseidon::<Fr>::new_circom(2)`
/// only fails on configuration mistakes, which is why most callers can
/// `?`-propagate at the outer level.
#[derive(Clone, Debug)]
pub struct ProtocolHasher {
    /// Current accumulator state.
    state: Fr,
}

impl ProtocolHasher {
    /// Start a new hasher with `seed` as the initial accumulator.
    ///
    /// `seed` is **not** hashed by itself — the first `absorb*` call
    /// produces `Poseidon2(seed, input)`. A `finalize` with no absorbs
    /// returns `seed` unchanged.
    pub fn new(seed: Fr) -> Self {
        Self { state: seed }
    }

    /// Absorb a single `Fr`.
    pub fn absorb(self, value: Fr) -> Result<Self, ProtocolError> {
        Ok(Self {
            state: poseidon2(self.state, value)?,
        })
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

/// Pairwise Poseidon2 over BN254 Fr. The 2-input arity is the iterated
/// building block for [`ProtocolHasher`]. Exposed for cases where a
/// caller genuinely needs a one-shot pair hash without a builder.
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
    fn finalize_without_absorb_returns_seed() {
        let seed = Fr::from(42u64);
        assert_eq!(ProtocolHasher::new(seed).finalize(), seed);
    }

    #[test]
    fn one_absorb_equals_poseidon2_seed_input() {
        let seed = Fr::from(1u64);
        let value = Fr::from(2u64);
        let from_builder = ProtocolHasher::new(seed).absorb(value).unwrap().finalize();
        let direct = poseidon2(seed, value).unwrap();
        assert_eq!(from_builder, direct);
    }

    #[test]
    fn absorb_u64_matches_absorb_fr() {
        let seed = Fr::from(1u64);
        let a = ProtocolHasher::new(seed).absorb_u64(7).unwrap().finalize();
        let b = ProtocolHasher::new(seed)
            .absorb(Fr::from(7u64))
            .unwrap()
            .finalize();
        assert_eq!(a, b);
    }

    #[test]
    fn absorb_many_equals_iterated_absorb() {
        let seed = Fr::from(1u64);
        let xs = [Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let chained = ProtocolHasher::new(seed)
            .absorb(xs[0])
            .unwrap()
            .absorb(xs[1])
            .unwrap()
            .absorb(xs[2])
            .unwrap()
            .finalize();
        let slice = ProtocolHasher::new(seed)
            .absorb_many(&xs)
            .unwrap()
            .finalize();
        assert_eq!(chained, slice);
    }

    #[test]
    fn matches_inline_iterated_poseidon2() {
        // Replicate the original pso-nft pattern inline and assert the
        // builder produces the same bytes.
        let seed = Fr::from(0x1111u64);
        let inputs = [
            Fr::from(0x2222u64),
            Fr::from(0x3333u64),
            Fr::from(0x4444u64),
        ];

        let mut expected = poseidon2(seed, inputs[0]).unwrap();
        expected = poseidon2(expected, inputs[1]).unwrap();
        expected = poseidon2(expected, inputs[2]).unwrap();

        let actual = ProtocolHasher::new(seed)
            .absorb_many(&inputs)
            .unwrap()
            .finalize();
        assert_eq!(actual, expected);
    }
}
