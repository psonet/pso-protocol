//! TributeDraft and SpendingUnit entity hashes.
//!
//! Each formula follows the iterated-Poseidon2 pattern that
//! `domain/pso-nft/` used to host. The TD id / TD hash are byte-identical
//! to the originals (parity enforced by the test module). The **SU hash**
//! additionally binds the two consent addresses (`attester`, `referrer`)
//! into its preimage — see [`compute_spending_unit_hash`] — so it
//! deliberately diverges from the pre-0.4 formula; the test module pins
//! its absorb order against a hand-rolled reference instead.
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
//! These functions take `worldwide_day` as an opaque `u64` and absorb it
//! as `Fr::from(wwd)`. The canonical encoding is the compact **`YYYYMMDD`**
//! date (e.g. `20250923`), matching the on-chain `SpendingUnitEntity` /
//! `TributeDraftEntity` `worldwideDay` field and the privacy-preserving L2
//! spec. The hash itself is format-agnostic — both sides must simply agree
//! on the same `u64`.

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
/// `amount_atto` is `u64` (not `u128`) — the on-chain
/// `TributeDraft` struct stores atto as a 64-bit value, and changing the
/// width would change the hash.
pub fn compute_tribute_draft_hash(
    id: &Fr,
    currency: u16,
    amount_base: u64,
    amount_atto: u64,
    su_ids: &[Fr],
) -> Result<Fr, ProtocolError> {
    Ok(ProtocolHasher::new(*id)
        .absorb_u64(u64::from(currency))?
        .absorb_u64(amount_base)?
        .absorb_u64(amount_atto)?
        .absorb_many(su_ids)?
        .finalize())
}

// ---------------------------------------------------------------------
// SpendingUnit
// ---------------------------------------------------------------------

/// Compute the SpendingUnit entity hash.
///
/// Iterated Poseidon2 over `id, owner, attester, referrer, worldwide_day,
/// currency, base, atto`, followed by each spending-record fingerprint,
/// followed by each amendment-record fingerprint.
///
/// `attester` and `referrer` are the SU's consent addresses (the SRA that
/// minted it and the wallet self-address captured at consent), each a
/// 20-byte EVM address right-aligned into an `Fr` (`uint160 → Fr`). They
/// sit immediately after `owner`, mirroring `SpendingUnitEntity`'s field
/// order, so the consent attribution is cryptographically bound to the
/// SU's identity (and thus to the ownership signature / aggregation proof)
/// rather than merely stored alongside it.
#[allow(clippy::too_many_arguments)]
pub fn compute_spending_unit_hash(
    id: &Fr,
    owner: &Fr,
    attester: &Fr,
    referrer: &Fr,
    worldwide_day: u64,
    currency: u16,
    amount_base: u64,
    amount_atto: u64,
    spending_record_fingerprints: &[Fr],
    amendment_record_fingerprints: &[Fr],
) -> Result<Fr, ProtocolError> {
    Ok(ProtocolHasher::new(*id)
        .absorb(*owner)?
        .absorb(*attester)?
        .absorb(*referrer)?
        .absorb_u64(worldwide_day)?
        .absorb_u64(u64::from(currency))?
        .absorb_u64(amount_base)?
        .absorb_u64(amount_atto)?
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

    // Hand-rolled iterated-Poseidon2 reference for the SU hash, matching
    // the documented preimage `[id, owner, attester, referrer, wwd,
    // currency, base, atto, sr.., ar..]`. Used to pin the absorb order.
    #[allow(clippy::too_many_arguments)]
    fn reference_su_hash(
        id: &Fr,
        owner: &Fr,
        attester: &Fr,
        referrer: &Fr,
        wwd: &Fr,
        currency_numeric: u16,
        amount_base: u64,
        amount_atto: u64,
        sr_fps: &[Fr],
        ar_fps: &[Fr],
    ) -> Fr {
        let mut poseidon = pso_poseidon::Poseidon::<Fr>::new_circom(2).unwrap();
        let mut result = poseidon.hash(&[*id, *owner]).unwrap();
        result = poseidon.hash(&[result, *attester]).unwrap();
        result = poseidon.hash(&[result, *referrer]).unwrap();
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
        let worldwide_day = 20_250_923u64; // YYYYMMDD
        let a = compute_tribute_draft_id(&owner, worldwide_day).unwrap();
        let b = compute_tribute_draft_id(&owner, worldwide_day).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn td_id_sensitive_to_each_input() {
        let owner = Fr::from(1u64);
        let worldwide_day = 20_250_923u64; // YYYYMMDD
        let next_day = 20_250_924u64;
        let h_owner_1 = compute_tribute_draft_id(&owner, worldwide_day).unwrap();
        let h_owner_2 = compute_tribute_draft_id(&Fr::from(2u64), worldwide_day).unwrap();
        let h_wwd_diff = compute_tribute_draft_id(&owner, next_day).unwrap();
        assert_ne!(h_owner_1, h_owner_2);
        assert_ne!(h_owner_1, h_wwd_diff);
    }

    // ----- TD Hash -----

    #[test]
    fn td_hash_parity_with_original_empty_su() {
        let id = Fr::from(0xdeadu64);
        let currency = 978u16;
        let amount_base = 100u64;
        let amount_atto = 0u64;
        let new = compute_tribute_draft_hash(&id, currency, amount_base, amount_atto, &[]).unwrap();
        let old = original_td_hash(&id, currency, amount_base, amount_atto, &[]);
        assert_eq!(new, old);
    }

    #[test]
    fn td_hash_parity_with_original_varied_su_counts() {
        let id = Fr::from(0xbeefu64);
        let currency = 840u16;
        let amount_base = 500u64;
        let amount_atto = 1u64;
        for n in [1usize, 2, 5, 10, 64] {
            let su_ids = fr_seq(1000 + n as u64, n);
            let new = compute_tribute_draft_hash(&id, currency, amount_base, amount_atto, &su_ids)
                .unwrap();
            let old = original_td_hash(&id, currency, amount_base, amount_atto, &su_ids);
            assert_eq!(new, old, "TD hash drift at n_su={n}");
        }
    }

    #[test]
    fn td_hash_sensitive_to_su_order() {
        // Iterated hashing is order-sensitive — reversing su_ids must
        // change the output.
        let id = Fr::from(1u64);
        let currency = 978u16;
        let amount_base = 0u64;
        let amount_atto = 0u64;
        let su = fr_seq(1, 4);
        let mut su_rev = su.clone();
        su_rev.reverse();
        let h1 = compute_tribute_draft_hash(&id, currency, amount_base, amount_atto, &su).unwrap();
        let h2 =
            compute_tribute_draft_hash(&id, currency, amount_base, amount_atto, &su_rev).unwrap();
        assert_ne!(h1, h2);
    }

    // ----- SU Hash -----

    #[test]
    fn su_hash_matches_reference_empty_records() {
        let id = Fr::from(0xc0deu64);
        let owner = Fr::from(0xf00du64);
        let att = Fr::from(0x5au64);
        let refr = Fr::from(0x7a11e7u64);
        let worldwide_day = 20_250_923u64; // YYYYMMDD
        let currency = 840u16;
        let amount_base = 100u64;
        let amount_atto = 0u64;
        let new = compute_spending_unit_hash(
            &id,
            &owner,
            &att,
            &refr,
            worldwide_day,
            currency,
            amount_base,
            amount_atto,
            &[],
            &[],
        )
        .unwrap();
        let reference = reference_su_hash(
            &id,
            &owner,
            &att,
            &refr,
            &Fr::from(worldwide_day),
            currency,
            amount_base,
            amount_atto,
            &[],
            &[],
        );
        assert_eq!(new, reference);
    }

    #[test]
    fn su_hash_matches_reference_varied_records() {
        let id = Fr::from(0xc0deu64);
        let owner = Fr::from(0xf00du64);
        let att = Fr::from(0x5au64);
        let refr = Fr::from(0x7a11e7u64);
        let worldwide_day = 20_250_923u64; // YYYYMMDD
        let currency = 978u16;
        let amount_base = 50u64;
        let amount_atto = 42u64;
        for (n_sr, n_ar) in [(0usize, 0usize), (1, 0), (0, 1), (3, 5), (10, 10)] {
            let sr = fr_seq(2000 + n_sr as u64, n_sr);
            let ar = fr_seq(3000 + n_ar as u64, n_ar);
            let new = compute_spending_unit_hash(
                &id,
                &owner,
                &att,
                &refr,
                worldwide_day,
                currency,
                amount_base,
                amount_atto,
                &sr,
                &ar,
            )
            .unwrap();
            let reference = reference_su_hash(
                &id,
                &owner,
                &att,
                &refr,
                &Fr::from(worldwide_day),
                currency,
                amount_base,
                amount_atto,
                &sr,
                &ar,
            );
            assert_eq!(new, reference, "SU hash drift at n_sr={n_sr} n_ar={n_ar}");
        }
    }

    #[test]
    fn su_hash_record_order_matters() {
        // Swapping the SR and AR positions must change the hash even
        // when both vectors contain the same elements — they enter the
        // chain at different points.
        let id = Fr::from(1u64);
        let owner = Fr::from(2u64);
        let att = Fr::from(3u64);
        let refr = Fr::from(4u64);
        let worldwide_day = 20_250_923u64; // YYYYMMDD
        let currency = 978u16; // ISO 4217 (EUR)
        let amount_base = 100u64;
        let amount_atto = 0u64;
        let v1 = fr_seq(1, 3);
        let v2 = fr_seq(4, 2);
        let h1 = compute_spending_unit_hash(
            &id,
            &owner,
            &att,
            &refr,
            worldwide_day,
            currency,
            amount_base,
            amount_atto,
            &v1,
            &v2,
        )
        .unwrap();
        let h2 = compute_spending_unit_hash(
            &id,
            &owner,
            &att,
            &refr,
            worldwide_day,
            currency,
            amount_base,
            amount_atto,
            &v2,
            &v1,
        )
        .unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn su_hash_sensitive_to_consent_addresses() {
        // The new attester / referrer fields must each change the hash —
        // proving the consent attribution is bound into the preimage.
        let id = Fr::from(1u64);
        let owner = Fr::from(2u64);
        let att = Fr::from(0x5au64);
        let refr = Fr::from(0x7a11e7u64);
        let worldwide_day = 20_250_923u64; // YYYYMMDD
        let currency = 978u16; // ISO 4217 (EUR)
        let amount_base = 100u64;
        let amount_atto = 0u64;

        // Hold every non-address field fixed; vary only attester / referrer.
        let su_hash = |attester: &Fr, referrer: &Fr| {
            compute_spending_unit_hash(
                &id,
                &owner,
                attester,
                referrer,
                worldwide_day,
                currency,
                amount_base,
                amount_atto,
                &[],
                &[],
            )
            .unwrap()
        };

        let base = su_hash(&att, &refr);
        let diff_att = su_hash(&Fr::from(0x5bu64), &refr);
        let diff_ref = su_hash(&att, &Fr::from(0x9999u64));
        // Zero (no-referrer / unset) must also differ from a set value.
        let zero_ref = su_hash(&att, &Fr::from(0u64));
        // attester and referrer occupy distinct positions: swapping them
        // (when distinct) changes the hash.
        let swapped = su_hash(&refr, &att);

        assert_ne!(base, diff_att, "attester must affect the hash");
        assert_ne!(base, diff_ref, "referrer must affect the hash");
        assert_ne!(base, zero_ref, "referrer=0 must differ from referrer set");
        assert_ne!(base, swapped, "attester/referrer are positionally distinct");
    }
}
