//! TributeDraft ↔ ZK-proof binding hash.
//!
//! The binding hash is the commitment that links an EVM-side
//! `TributeDraft` submission to its off-chain ZK proof. It hashes
//! `(sender, tribute_draft_id, chain_id)` into a single BN254 field
//! element using single-shot Poseidon4 with the two-limb decomposition
//! described below.
//!
//! ## Bound to precompile `0x0210`
//!
//! Any change to the byte layout, limb decomposition, or arity is a
//! consensus-breaking change. The Solidity wrapper
//! `solidity/PsoProtocol.sol::computeBindingHash` calls precompile
//! `0x0210` which delegates back to this exact function.
//!
//! ## Byte layout
//!
//! The four inputs to Poseidon4 are produced as follows:
//!
//! | Field           | Source                                | Decoding                                            |
//! | --------------- | ------------------------------------- | --------------------------------------------------- |
//! | `sender_fr`     | EVM address (20 BE bytes)             | Zero-pad to 32 BE bytes, `Fr::from_be_bytes_mod_order`. |
//! | `tdid_lo`       | Lower 128 bits of `tributeDraftId`    | `bytes[16..32]` of the BE `uint256`.                |
//! | `tdid_hi`       | Upper 128 bits of `tributeDraftId`    | `bytes[0..16]` of the BE `uint256`.                 |
//! | `chainid_fr`    | EVM chain id (u64)                    | `Fr::from(chain_id)`. The on-chain side passes the full `uint256` and the precompile mod-reduces; values < 2^64 are byte-identical. |
//!
//! Splitting `tdid` into two 128-bit limbs avoids BN254 Fr overflow:
//! the scalar modulus is ≈ 2^253.6, so a full 256-bit value cannot fit
//! in one Fr without ambiguous reduction.

use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::error::ProtocolError;
use crate::fr::split_u256_be_into_limbs;
use crate::hash::poseidon4;

/// Compute the TributeDraft ↔ ZK-proof binding hash.
///
/// Mirrors `TributeDraft._bindingHash` byte-for-byte, and the legacy
/// inline copies in `pso_mobile_integration::api::compute_binding_hash`
/// and `pso_zk_cli::commands::aggregate::compute_binding_hash`.
///
/// # Inputs
///
/// - `sender`: 20-byte EVM address, big-endian.
/// - `tribute_draft_id`: 32-byte `uint256` id, big-endian.
/// - `chain_id`: EVM chain id, fits in `u64` by spec.
///
/// # Returns
///
/// A single BN254 `Fr` digest. Encode as 32 big-endian bytes when
/// crossing the chain boundary (see `fr::fr_to_be_bytes`).
pub fn compute_binding_hash(
    sender: &[u8; 20],
    tribute_draft_id: &[u8; 32],
    chain_id: u64,
) -> Result<Fr, ProtocolError> {
    // Pad the 20-byte sender into a 32-byte BE slot (left-padded).
    let mut sender_be32 = [0u8; 32];
    sender_be32[12..32].copy_from_slice(sender);
    let sender_fr = Fr::from_be_bytes_mod_order(&sender_be32);

    // Split the 256-bit tributeDraftId into two 128-bit limbs.
    let [tdid_lo, tdid_hi] = split_u256_be_into_limbs(tribute_draft_id);

    let chainid_fr = Fr::from(chain_id);

    poseidon4(sender_fr, tdid_lo, tdid_hi, chainid_fr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{BigInteger, PrimeField};
    use pso_poseidon::PoseidonHasher;

    /// Inline-replicates the original
    /// `pso_mobile_integration::api::compute_binding_hash` byte
    /// manipulations and Poseidon call. Asserting equality with
    /// `compute_binding_hash` proves the refactor preserves bytes —
    /// the whole reason this crate exists.
    fn original_inline(sender: &[u8], tribute_draft_id: &[u8], chain_id: u64) -> Fr {
        let mut sender_le = [0u8; 32];
        for (i, b) in sender.iter().rev().enumerate() {
            sender_le[i] = *b;
        }
        let sender_fr = Fr::from_le_bytes_mod_order(&sender_le);

        let mut tdid_lo_le = [0u8; 32];
        for (i, b) in tribute_draft_id[16..32].iter().rev().enumerate() {
            tdid_lo_le[i] = *b;
        }
        let tdid_lo_fr = Fr::from_le_bytes_mod_order(&tdid_lo_le);

        let mut tdid_hi_le = [0u8; 32];
        for (i, b) in tribute_draft_id[0..16].iter().rev().enumerate() {
            tdid_hi_le[i] = *b;
        }
        let tdid_hi_fr = Fr::from_le_bytes_mod_order(&tdid_hi_le);

        let chainid_fr = Fr::from(chain_id);

        let mut poseidon = pso_poseidon::Poseidon::<Fr>::new_circom(4).unwrap();
        poseidon
            .hash(&[sender_fr, tdid_lo_fr, tdid_hi_fr, chainid_fr])
            .unwrap()
    }

    fn sample_sender() -> [u8; 20] {
        [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]
    }

    fn sample_tdid() -> [u8; 32] {
        // Non-trivial value spanning both 128-bit limbs.
        [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // upper 8 of hi limb
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, // lower 8 of hi limb
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, // upper 8 of lo limb
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, // lower 8 of lo limb
        ]
    }

    #[test]
    fn deterministic() {
        let s = sample_sender();
        let t = sample_tdid();
        let a = compute_binding_hash(&s, &t, 1234).unwrap();
        let b = compute_binding_hash(&s, &t, 1234).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn parity_with_original_inline() {
        let s = sample_sender();
        let t = sample_tdid();
        for chain_id in [0u64, 1, 10, 8453, 84532, u64::MAX] {
            let new_impl = compute_binding_hash(&s, &t, chain_id).unwrap();
            let old_impl = original_inline(&s, &t, chain_id);
            assert_eq!(
                new_impl, old_impl,
                "byte drift vs original at chain_id={chain_id}"
            );
        }
    }

    #[test]
    fn parity_with_original_across_random_inputs() {
        // Deterministic pseudo-random inputs (no rand crate dep) — vary
        // every byte so any byte-order mistake shows up.
        for seed in 0u8..16 {
            let mut sender = [0u8; 20];
            let mut tdid = [0u8; 32];
            for (i, b) in sender.iter_mut().enumerate() {
                *b = seed.wrapping_mul(7).wrapping_add(i as u8);
            }
            for (i, b) in tdid.iter_mut().enumerate() {
                *b = seed.wrapping_mul(13).wrapping_add(i as u8);
            }
            let chain_id = u64::from(seed) * 1_000_000 + 31337;
            let new_impl = compute_binding_hash(&sender, &tdid, chain_id).unwrap();
            let old_impl = original_inline(&sender, &tdid, chain_id);
            assert_eq!(new_impl, old_impl, "drift at seed={seed}");
        }
    }

    #[test]
    fn sender_sensitivity() {
        let t = sample_tdid();
        let a = compute_binding_hash(&[0u8; 20], &t, 1).unwrap();
        let mut s2 = [0u8; 20];
        s2[19] = 1;
        let b = compute_binding_hash(&s2, &t, 1).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn tdid_limb_sensitivity() {
        // Flipping a bit in the lower limb vs the upper limb must
        // produce different outputs — verifies the split is wired the
        // right way around.
        let s = sample_sender();

        let mut t_base = [0u8; 32];
        t_base[31] = 1; // lower limb has bit 0 set
        let lo_set = compute_binding_hash(&s, &t_base, 1).unwrap();

        let mut t_hi = [0u8; 32];
        t_hi[15] = 1; // upper limb has bit 0 set
        let hi_set = compute_binding_hash(&s, &t_hi, 1).unwrap();

        assert_ne!(lo_set, hi_set);
    }

    #[test]
    fn chain_id_sensitivity() {
        let s = sample_sender();
        let t = sample_tdid();
        let a = compute_binding_hash(&s, &t, 1).unwrap();
        let b = compute_binding_hash(&s, &t, 2).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn output_fits_in_32_bytes_be() {
        // Sanity check on the encoding contract: every output we
        // return must be representable as 32 BE bytes (Fr is 254-bit).
        let s = sample_sender();
        let t = sample_tdid();
        let h = compute_binding_hash(&s, &t, 1).unwrap();
        let bytes = h.into_bigint().to_bytes_be();
        assert!(bytes.len() <= 32);
    }
}
