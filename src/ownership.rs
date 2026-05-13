//! Ownership commitment.
//!
//! `Poseidon3(pk.x, pk.y, nonce)` over the **Grumpkin** public-key
//! coordinates plus a per-NFT nonce. The resulting `Fr` is the stored
//! `derivedOwner` value on every PSO NFT; the ZK circuit re-derives
//! it from the wallet's private key inside the proof.
//!
//! ## Bound to the ZK circuit (Noir source)
//!
//! Ownership is **not** exposed as a precompile. The chain never
//! recomputes it -- the proof's public-input vector carries the
//! `derivedOwner` and the circuit asserts internally that it equals
//! `Poseidon3(pk.x, pk.y, nonce)`. Changing the formula here requires
//! recompiling the Noir circuit and updating the canonical descriptor.
//!
//! ## Curve choice
//!
//! Grumpkin is BN254's "embedded curve" -- its base field is BN254's
//! scalar field. Coordinates fit in a single `Fr` each (no limb
//! decomposition needed), and in-circuit EC arithmetic is a native
//! foreign call (`std::embedded_curve_ops::multi_scalar_mul`). This
//! replaces the previous secp256k1 path, which cost ~42k constraints
//! per signature verify due to non-native EC emulation.

use ark_bn254::Fr;

use crate::error::ProtocolError;
use crate::hash::poseidon3;

/// Compute the ownership commitment from Grumpkin public-key
/// coordinates and a nonce.
///
/// `pk_x` / `pk_y` are Grumpkin x/y coordinates as `Fr`. The wallet
/// derives them by interpreting the HKDF output of the App. A
/// shared-secret derivation as a Grumpkin scalar, then computing
/// `shared_pk = shared_sk * G_Grumpkin`.
pub fn compute_ownership(pk_x: Fr, pk_y: Fr, nonce: Fr) -> Result<Fr, ProtocolError> {
    poseidon3(pk_x, pk_y, nonce)
}

/// Alias retained for forward-compat with `pso-zk-circuit-noir`
/// testing helpers that import a Grumpkin-flavored name. Same body
/// as [`compute_ownership`].
pub fn compute_ownership_grumpkin(
    pk_x: Fr,
    pk_y: Fr,
    nonce: Fr,
) -> Result<Fr, ProtocolError> {
    compute_ownership(pk_x, pk_y, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let pk_x = Fr::from(7u64);
        let pk_y = Fr::from(11u64);
        let nonce = Fr::from(42u64);
        let a = compute_ownership(pk_x, pk_y, nonce).unwrap();
        let b = compute_ownership(pk_x, pk_y, nonce).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_nonces_differ() {
        let pk_x = Fr::from(7u64);
        let pk_y = Fr::from(11u64);
        let a = compute_ownership(pk_x, pk_y, Fr::from(1u64)).unwrap();
        let b = compute_ownership(pk_x, pk_y, Fr::from(2u64)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_pks_differ() {
        let nonce = Fr::from(42u64);
        let a = compute_ownership(Fr::from(1u64), Fr::from(2u64), nonce).unwrap();
        let b = compute_ownership(Fr::from(3u64), Fr::from(4u64), nonce).unwrap();
        assert_ne!(a, b);
    }
}
