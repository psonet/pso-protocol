//! Ownership commitment.
//!
//! `Poseidon5(pk_x_lo, pk_x_hi, pk_y_lo, pk_y_hi, nonce)` over the
//! decomposed secp256k1 public-key coordinates plus a per-NFT nonce.
//! The resulting `Fr` is the stored `derivedOwner` value on every PSO
//! NFT; the ZK circuit re-derives it from the wallet's private key
//! inside the proof.
//!
//! ## Bound to the ZK circuit (Noir source)
//!
//! Ownership is **not** exposed as a precompile. The chain never
//! recomputes it — the proof's public-input vector carries the
//! `derivedOwner` and the circuit asserts internally that it equals
//! `Poseidon5(...)`. Changing the formula here requires recompiling
//! the Noir circuit and updating the canonical descriptor.
//!
//! ## Coordinate decomposition
//!
//! Each 32-byte big-endian SEC1 coordinate is split into two 128-bit
//! `Fr` limbs. **The decomposition is _not_ a clean BE uint256 split**
//! — it interprets each 16-byte chunk of the BE coordinate as a
//! _little-endian_ u128. That is the exact convention the original
//! `pso-zk-core::generate_ownership` used, and the Noir circuit was
//! compiled against this layout. Do not "fix" the apparent endianness
//! mismatch: it would be a consensus-breaking change.

use ark_bn254::Fr;

use crate::error::ProtocolError;
use crate::hash::poseidon5;

/// Compute the ownership commitment.
///
/// Mirrors `pso_zk_core::generate_ownership` byte-for-byte. Takes the
/// secp256k1 public-key coordinates as raw 32-byte big-endian arrays
/// — k256 (or any other curve library) decoding lives upstream in
/// `pso-integration`, keeping this crate free of an EC dependency.
///
/// # Inputs
///
/// - `pk_x_be`: 32-byte BE encoding of the public-key X coordinate (SEC1).
/// - `pk_y_be`: 32-byte BE encoding of the public-key Y coordinate (SEC1).
/// - `nonce`: per-NFT randomness chosen at mint time.
pub fn compute_ownership(
    pk_x_be: &[u8; 32],
    pk_y_be: &[u8; 32],
    nonce: Fr,
) -> Result<Fr, ProtocolError> {
    let [x_lo, x_hi] = decompose_coordinate(pk_x_be);
    let [y_lo, y_hi] = decompose_coordinate(pk_y_be);
    poseidon5(x_lo, x_hi, y_lo, y_hi, nonce)
}

/// Decompose a 32-byte big-endian SEC1 coordinate into two 128-bit
/// `Fr` limbs by reading **each 16-byte half as little-endian** u128.
///
/// This is **deliberately not** a BE uint256 → (lo, hi) split — see
/// the module-level docs. Returns `[half_lo, half_hi]` where
/// `half_lo` is the LE-decode of `bytes[0..16]` and `half_hi` is the
/// LE-decode of `bytes[16..32]`.
fn decompose_coordinate(bytes: &[u8; 32]) -> [Fr; 2] {
    let mut limbs = [Fr::from(0u64); 2];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut value = 0u128;
        let start = i * 16;
        for j in 0..16 {
            value |= u128::from(bytes[start + j]) << (j * 8);
        }
        *limb = Fr::from(value);
    }
    limbs
}

#[cfg(test)]
mod tests {
    use super::*;
    use pso_poseidon::PoseidonHasher;

    /// Inline replica of the original `pso_zk_core::generate_ownership`
    /// using only `&[u8; 32]` inputs (no k256). Proves the new function
    /// preserves the formula's byte layout.
    fn original_inline(pk_x_be: &[u8; 32], pk_y_be: &[u8; 32], nonce: Fr) -> Fr {
        // Same byte-shift decomposition as `pso_zk_core::nft::decompose_to_limbs`.
        let mut x_limbs = [Fr::from(0u64); 2];
        let mut y_limbs = [Fr::from(0u64); 2];
        for i in 0..2 {
            let mut xv = 0u128;
            let mut yv = 0u128;
            let start = i * 16;
            for j in 0..16 {
                xv |= u128::from(pk_x_be[start + j]) << (j * 8);
                yv |= u128::from(pk_y_be[start + j]) << (j * 8);
            }
            x_limbs[i] = Fr::from(xv);
            y_limbs[i] = Fr::from(yv);
        }

        let mut pk_limbs = Vec::with_capacity(5);
        pk_limbs.extend(x_limbs);
        pk_limbs.extend(y_limbs);
        pk_limbs.push(nonce);

        let mut hasher = pso_poseidon::Poseidon::<Fr>::new_circom(5).unwrap();
        hasher.hash(&pk_limbs).unwrap()
    }

    fn sample_x() -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(7).wrapping_add(0x55);
        }
        b
    }

    fn sample_y() -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(13).wrapping_add(0xaa);
        }
        b
    }

    #[test]
    fn parity_with_original_inline() {
        let x = sample_x();
        let y = sample_y();
        for nonce_seed in [0u64, 1, 42, 0xdeadbeef, u64::MAX] {
            let nonce = Fr::from(nonce_seed);
            let new_impl = compute_ownership(&x, &y, nonce).unwrap();
            let old_impl = original_inline(&x, &y, nonce);
            assert_eq!(
                new_impl, old_impl,
                "ownership drift at nonce_seed={nonce_seed}"
            );
        }
    }

    #[test]
    fn deterministic() {
        let x = sample_x();
        let y = sample_y();
        let nonce = Fr::from(1u64);
        let a = compute_ownership(&x, &y, nonce).unwrap();
        let b = compute_ownership(&x, &y, nonce).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_nonces_differ() {
        let x = sample_x();
        let y = sample_y();
        let a = compute_ownership(&x, &y, Fr::from(1u64)).unwrap();
        let b = compute_ownership(&x, &y, Fr::from(2u64)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_pks_differ() {
        let nonce = Fr::from(42u64);
        let x1 = sample_x();
        let mut x2 = sample_x();
        x2[0] = x2[0].wrapping_add(1);
        let y = sample_y();
        let a = compute_ownership(&x1, &y, nonce).unwrap();
        let b = compute_ownership(&x2, &y, nonce).unwrap();
        assert_ne!(a, b);

        // y-coord sensitivity too.
        let mut y2 = y;
        y2[31] = y2[31].wrapping_add(1);
        let c = compute_ownership(&x1, &y2, nonce).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn coordinate_decomposition_layout() {
        // Sanity-check the limb layout: putting a known byte in
        // bytes[0] should land in the LSB of `limb_lo`, and bytes[16]
        // should land in the LSB of `limb_hi`.
        let mut b = [0u8; 32];
        b[0] = 0xab;
        b[16] = 0xcd;
        let [lo, hi] = decompose_coordinate(&b);
        assert_eq!(lo, Fr::from(0xabu64));
        assert_eq!(hi, Fr::from(0xcdu64));
    }
}
