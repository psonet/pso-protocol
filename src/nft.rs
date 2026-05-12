//! TributeDraft and SpendingUnit entity hashes.
//!
//! Each formula is structurally identical to the iterated-Poseidon2
//! patterns that `domain/pso-nft/` used to host. Output bytes are
//! guaranteed identical — parity is enforced by the test module which
//! inline-replicates the original implementations and asserts equality.
//!
//! ## Bound to precompiles `0x0211`, `0x0212`
//!
//! | Address  | Function                  |
//! | -------- | ------------------------- |
//! | `0x0211` | [`compute_tribute_draft_hash`] |
//! | `0x0212` | [`compute_spending_unit_hash`] |
//!
//! There is **no precompile for TD-id or SU-id**.
//! [`compute_tribute_draft_id`] stays here for wallet use at mint time
//! but never gets a chain-side address: the formula's `owner` input
//! bakes in off-chain nonce randomness, and SU ids are random by
//! construction. In both cases the ZK proof is the only legitimate
//! witness — on-chain recomputation gives no guarantee the proof
//! doesn't already provide.
//!
//! Any change to these formulas is a consensus-breaking change requiring
//! a coordinated hardfork — see `README.md`.
//!
//! ## Worldwide day
//!
//! These functions take `worldwide_day` as a `u64`. Callers convert from
//! `NaiveDate` upstream via `(date - epoch).num_days() as u64` where the
//! epoch is `2021-01-01`. The encoding into Fr is `Fr::from(wwd_u64)`,
//! which mirrors the original `Fr::from(worldwide_day_count(&date)?)`
//! byte-for-byte.

use ark_bn254::Fr;

use crate::error::ProtocolError;
use crate::hash::ProtocolHasher;

// ---------------------------------------------------------------------
// TributeDraft
// ---------------------------------------------------------------------

/// Compute the TributeDraft entity id.
///
/// `Poseidon2(owner, worldwide_day)`. Mirrors the original
/// `pso_nft::compute_tribute_draft_id` byte-for-byte.
pub fn compute_tribute_draft_id(owner: &Fr, worldwide_day: u64) -> Result<Fr, ProtocolError> {
    Ok(ProtocolHasher::new(*owner)
        .absorb_u64(worldwide_day)?
        .finalize())
}

/// Compute the TributeDraft entity hash.
///
/// Iterated Poseidon2 starting from `Poseidon2(id, currency)`, then
/// chaining each subsequent field. Mirrors the original
/// `pso_nft::compute_tribute_draft_hash` byte-for-byte.
///
/// `settlement_amount_atto` is `u64` (not `u128`) — the on-chain
/// `TributeDraft` struct stores atto as a 64-bit value, and changing the
/// width would change the hash.
pub fn compute_tribute_draft_hash(
    id: &Fr,
    settlement_currency: u16,
    settlement_amount_base: u64,
    settlement_amount_atto: u64,
    su_ids: &[Fr],
) -> Result<Fr, ProtocolError> {
    Ok(ProtocolHasher::new(*id)
        .absorb_u64(u64::from(settlement_currency))?
        .absorb_u64(settlement_amount_base)?
        .absorb_u64(settlement_amount_atto)?
        .absorb_many(su_ids)?
        .finalize())
}

// ---------------------------------------------------------------------
// SpendingUnit
// ---------------------------------------------------------------------

/// Compute the SpendingUnit entity hash.
///
/// Iterated Poseidon2 over `id, owner, worldwide_day, currency, base,
/// atto`, followed by each spending-record fingerprint, followed by each
/// amendment-record fingerprint. Mirrors the original
/// `pso_nft::compute_spending_unit_hash` byte-for-byte.
#[allow(clippy::too_many_arguments)]
pub fn compute_spending_unit_hash(
    id: &Fr,
    owner: &Fr,
    worldwide_day: u64,
    settlement_currency: u16,
    settlement_amount_base: u64,
    settlement_amount_atto: u64,
    spending_record_fingerprints: &[Fr],
    amendment_record_fingerprints: &[Fr],
) -> Result<Fr, ProtocolError> {
    Ok(ProtocolHasher::new(*id)
        .absorb(*owner)?
        .absorb_u64(worldwide_day)?
        .absorb_u64(u64::from(settlement_currency))?
        .absorb_u64(settlement_amount_base)?
        .absorb_u64(settlement_amount_atto)?
        .absorb_many(spending_record_fingerprints)?
        .absorb_many(amendment_record_fingerprints)?
        .finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pso_poseidon::PoseidonHasher;

    // ----- Inline replicas of the original pso-nft implementations -----

    fn original_td_id(owner: &Fr, wwd: &Fr) -> Fr {
        let mut poseidon = pso_poseidon::Poseidon::<Fr>::new_circom(2).unwrap();
        poseidon.hash(&[*owner, *wwd]).unwrap()
    }

    fn original_td_hash(
        id: &Fr,
        currency_numeric: u16,
        amount_base: u64,
        amount_atto: u64,
        su_ids: &[Fr],
    ) -> Fr {
        let mut poseidon = pso_poseidon::Poseidon::<Fr>::new_circom(2).unwrap();
        let mut result = poseidon
            .hash(&[*id, Fr::from(u64::from(currency_numeric))])
            .unwrap();
        result = poseidon.hash(&[result, Fr::from(amount_base)]).unwrap();
        result = poseidon.hash(&[result, Fr::from(amount_atto)]).unwrap();
        for su_id in su_ids {
            result = poseidon.hash(&[result, *su_id]).unwrap();
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn original_su_hash(
        id: &Fr,
        owner: &Fr,
        wwd: &Fr,
        currency_numeric: u16,
        amount_base: u64,
        amount_atto: u64,
        sr_fps: &[Fr],
        ar_fps: &[Fr],
    ) -> Fr {
        let mut poseidon = pso_poseidon::Poseidon::<Fr>::new_circom(2).unwrap();
        let mut result = poseidon.hash(&[*id, *owner]).unwrap();
        result = poseidon.hash(&[result, *wwd]).unwrap();
        result = poseidon
            .hash(&[result, Fr::from(u64::from(currency_numeric))])
            .unwrap();
        result = poseidon.hash(&[result, Fr::from(amount_base)]).unwrap();
        result = poseidon.hash(&[result, Fr::from(amount_atto)]).unwrap();
        for sr in sr_fps {
            result = poseidon.hash(&[result, *sr]).unwrap();
        }
        for ar in ar_fps {
            result = poseidon.hash(&[result, *ar]).unwrap();
        }
        result
    }

    // ----- Test helpers -----

    fn fr_seq(seed: u64, n: usize) -> Vec<Fr> {
        (0..n)
            .map(|i| Fr::from(seed.wrapping_add(i as u64)))
            .collect()
    }

    // ----- TD ID -----

    #[test]
    fn td_id_parity_with_original() {
        for (owner_seed, wwd) in [(0u64, 0u64), (1, 1), (42, 7331), (u64::MAX, u64::MAX)] {
            let owner = Fr::from(owner_seed);
            let new = compute_tribute_draft_id(&owner, wwd).unwrap();
            let old = original_td_id(&owner, &Fr::from(wwd));
            assert_eq!(new, old, "TD id drift at owner_seed={owner_seed} wwd={wwd}");
        }
    }

    #[test]
    fn td_id_deterministic() {
        let owner = Fr::from(123u64);
        let a = compute_tribute_draft_id(&owner, 456).unwrap();
        let b = compute_tribute_draft_id(&owner, 456).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn td_id_sensitive_to_each_input() {
        let owner = Fr::from(1u64);
        let h_owner_1 = compute_tribute_draft_id(&owner, 100).unwrap();
        let h_owner_2 = compute_tribute_draft_id(&Fr::from(2u64), 100).unwrap();
        let h_wwd_diff = compute_tribute_draft_id(&owner, 101).unwrap();
        assert_ne!(h_owner_1, h_owner_2);
        assert_ne!(h_owner_1, h_wwd_diff);
    }

    // ----- TD Hash -----

    #[test]
    fn td_hash_parity_with_original_empty_su() {
        let id = Fr::from(0xdeadu64);
        let new = compute_tribute_draft_hash(&id, 978, 100, 0, &[]).unwrap();
        let old = original_td_hash(&id, 978, 100, 0, &[]);
        assert_eq!(new, old);
    }

    #[test]
    fn td_hash_parity_with_original_varied_su_counts() {
        let id = Fr::from(0xbeefu64);
        for n in [1usize, 2, 5, 10, 64] {
            let su_ids = fr_seq(1000 + n as u64, n);
            let new = compute_tribute_draft_hash(&id, 840, 500, 1, &su_ids).unwrap();
            let old = original_td_hash(&id, 840, 500, 1, &su_ids);
            assert_eq!(new, old, "TD hash drift at n_su={n}");
        }
    }

    #[test]
    fn td_hash_sensitive_to_su_order() {
        // Iterated hashing is order-sensitive — reversing su_ids must
        // change the output.
        let id = Fr::from(1u64);
        let su = fr_seq(1, 4);
        let mut su_rev = su.clone();
        su_rev.reverse();
        let h1 = compute_tribute_draft_hash(&id, 978, 0, 0, &su).unwrap();
        let h2 = compute_tribute_draft_hash(&id, 978, 0, 0, &su_rev).unwrap();
        assert_ne!(h1, h2);
    }

    // ----- SU Hash -----

    #[test]
    fn su_hash_parity_with_original_empty_records() {
        let id = Fr::from(0xc0deu64);
        let owner = Fr::from(0xf00du64);
        let new = compute_spending_unit_hash(&id, &owner, 12345, 840, 100, 0, &[], &[]).unwrap();
        let old = original_su_hash(&id, &owner, &Fr::from(12345u64), 840, 100, 0, &[], &[]);
        assert_eq!(new, old);
    }

    #[test]
    fn su_hash_parity_with_original_varied_records() {
        let id = Fr::from(0xc0deu64);
        let owner = Fr::from(0xf00du64);
        for (n_sr, n_ar) in [(0usize, 0usize), (1, 0), (0, 1), (3, 5), (10, 10)] {
            let sr = fr_seq(2000 + n_sr as u64, n_sr);
            let ar = fr_seq(3000 + n_ar as u64, n_ar);
            let new = compute_spending_unit_hash(&id, &owner, 100, 978, 50, 42, &sr, &ar).unwrap();
            let old = original_su_hash(&id, &owner, &Fr::from(100u64), 978, 50, 42, &sr, &ar);
            assert_eq!(new, old, "SU hash drift at n_sr={n_sr} n_ar={n_ar}");
        }
    }

    #[test]
    fn su_hash_record_order_matters() {
        // Swapping the SR and AR positions must change the hash even
        // when both vectors contain the same elements — they enter the
        // chain at different points.
        let id = Fr::from(1u64);
        let owner = Fr::from(2u64);
        let v1 = fr_seq(1, 3);
        let v2 = fr_seq(4, 2);
        let h1 = compute_spending_unit_hash(&id, &owner, 1, 1, 1, 1, &v1, &v2).unwrap();
        let h2 = compute_spending_unit_hash(&id, &owner, 1, 1, 1, 1, &v2, &v1).unwrap();
        assert_ne!(h1, h2);
    }
}
