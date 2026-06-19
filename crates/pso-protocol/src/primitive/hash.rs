//! Pluggable field hash.
//!
//! Two operations cover every PSO hashing need:
//!
//! - [`FieldHasher::hash`] — fixed-arity single-shot (Poseidon-2/3/4/5).
//!   Used for the owner commitment, the binding hash, Merkle nodes, and
//!   the signing payload.
//! - [`FieldHasher::iterate`] — iterated 2-to-1 over a seed. Used for
//!   entity hashes (`ProtocolHasher` in the legacy crate). Default impl
//!   is `fold(seed, |acc, x| hash([acc, x]))`, so an instance only has to
//!   provide `hash`.
//!
//! Swapping this type changes *every* hash in the protocol at once and
//! consistently — owner, entity, payload, binding, and the signature
//! challenge all route through the suite's `Hash`. (An insecure additive
//! `AddHash` instance lives in the core crate's tests, to prove that.)

use ark_ff::PrimeField;

use crate::error::Error;

/// A hash over a prime field.
pub trait FieldHasher<F: PrimeField>: 'static {
    /// Fixed-arity hash of `inputs`.
    fn hash(inputs: &[F]) -> Result<F, Error>;

    /// Iterated 2-to-1 hash: `state = hash([state, x])` folded over
    /// `body`, seeded at `seed`. `iterate(seed, [])` returns `seed`.
    fn iterate(seed: F, body: &[F]) -> Result<F, Error> {
        let mut state = seed;
        for x in body {
            state = Self::hash(&[state, *x])?;
        }
        Ok(state)
    }
}

// ----------------------------------------------------------------------
// Poseidon2 instance — the production hash.
// ----------------------------------------------------------------------

/// BN254 Poseidon2 via `pso-poseidon` — bit-identical to noir's in-circuit
/// `poseidon2` (the sponge over the bb `poseidon2_permutation`). One sponge
/// covers every arity, so unlike the circom Poseidon1 it predates there are no
/// per-width parameter sets. `hash` is total (the sponge can't fail), so the
/// `Result` is always `Ok` — kept for the [`FieldHasher`] signature.
pub struct Poseidon2;

impl FieldHasher<ark_bn254::Fr> for Poseidon2 {
    fn hash(inputs: &[ark_bn254::Fr]) -> Result<ark_bn254::Fr, Error> {
        use pso_poseidon::PoseidonHasher as _;
        Ok(pso_poseidon::Poseidon2::new()
            .hash(inputs)
            .expect("poseidon2 sponge is infallible"))
    }
}
