//! Pluggable key-derivation function.
//!
//! Used by the key-origin paths (consent-box ECDH→key, local random) to
//! derive material in the native field. Field-valued (`F -> F`) rather
//! than byte-valued so derived secrets land in the same space as nonces
//! and can be re-derived/proved in-circuit if needed.

use ark_ff::PrimeField;

use crate::error::Error;

/// A domain-separated field KDF.
pub trait Kdf<F: PrimeField>: 'static {
    /// Domain separator folded into the derivation.
    const DOMAIN: &'static str;
    /// Derive one field element from `inputs`.
    fn derive(inputs: &[F]) -> Result<F, Error>;
}

/// Poseidon-based KDF (reuses the suite's hash discipline; here pinned to
/// BN254 Poseidon). Production HKDF→scalar can be a second instance.
pub struct PoseidonKdf;

impl Kdf<ark_bn254::Fr> for PoseidonKdf {
    const DOMAIN: &'static str = "PSO/kdf/poseidon/v1";

    fn derive(inputs: &[ark_bn254::Fr]) -> Result<ark_bn254::Fr, Error> {
        use crate::primitive::hash::{FieldHasher, Poseidon2};
        let tag = ark_bn254::Fr::from_le_bytes_mod_order(Self::DOMAIN.as_bytes());
        let mut v = Vec::with_capacity(inputs.len() + 1);
        v.push(tag);
        v.extend_from_slice(inputs);

        Poseidon2::hash(&v)
    }
}
