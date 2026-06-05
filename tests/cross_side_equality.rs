//! Cross-side equality harness — Rust ↔ Solidity byte equality for every
//! precompile-bound hash this crate publishes.
//!
//! ## What this proves
//!
//! For each canonical hash exposed by `pso-protocol`, the **same input**
//! produces the **same 32 bytes** whether computed:
//!
//! - directly via the published Rust function, or
//! - via the Solidity wrapper in `solidity/PsoProtocol.sol`, which
//!   tightly-packs its arguments and `staticcall`s a precompile that
//!   delegates back to the same Rust function.
//!
//! Drift between the two would silently break proof verification across
//! the off-chain ↔ on-chain boundary, which is precisely what this
//! crate's extraction exists to prevent.
//!
//! ## How it works
//!
//! 1. The `solidity_*_input` builders below replicate the exact
//!    `abi.encodePacked(...)` byte layout each Solidity wrapper emits.
//!    These layouts are documented in `solidity/PsoProtocol.sol` and
//!    pinned end-to-end by the Foundry tests in
//!    `solidity/PsoProtocol.t.sol` (which use `vm.mockCall(expectedInput, …)`
//!    to assert the wrapper sends exactly these bytes).
//!
//! 2. The `precompile::*` bodies below decode that calldata and call the
//!    `pso-protocol` Rust function — option (a) from the design brief
//!    (re-implement minimally in test code, line-for-line equivalent to
//!    `pso-chain/crates/pso-chain-node/src/precompile/protocol_*.rs`).
//!    Re-implementing here, rather than depending on `pso-chain`, keeps
//!    this crate dependency-light and respects the one-way dependency
//!    direction (`pso-chain` → `pso-protocol`).
//!
//! 3. For each hash we assert `direct_rust_bytes == precompile_bytes`
//!    on fixed vectors *and* on property-generated inputs.
//!
//! Any divergence in (a) the documented wrapper calldata layout,
//! (b) the precompile body's input decoding, or (c) the Rust formula
//! itself produces a test failure.
//!
//! ## Precompile coverage
//!
//! | Address  | Rust formula                                    | Solidity wrapper                       | Tests                                          |
//! | -------- | ----------------------------------------------- | -------------------------------------- | ---------------------------------------------- |
//! | `0x0210` | `pso_protocol::binding::compute_binding_hash`   | `PsoProtocol.computeBindingHash`       | `binding_hash_fixed_vector`, `binding_hash_property` |
//! | `0x0211` | `pso_protocol::nft::compute_tribute_draft_hash` | `PsoProtocol.computeTributeDraftHash`  | `td_hash_fixed_*`, `td_hash_property`          |
//! | `0x0212` | `pso_protocol::nft::compute_spending_unit_hash` | `PsoProtocol.computeSpendingUnitHash`  | `su_hash_fixed_*`, `su_hash_property`          |
//!
//! `0x0213..0x021F` are reserved; no Solidity wrapper or Rust formula
//! exists yet. When a new precompile lands, add a section here.
//!
//! `compute_tribute_draft_id` has no precompile by design — see
//! `solidity/PsoProtocol.sol` for the rationale (TD-id bakes in
//! off-chain nonce randomness; on-chain recomputation adds nothing the
//! ZK proof doesn't already attest).

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use proptest::prelude::*;

use pso_protocol::binding::compute_binding_hash;
use pso_protocol::fr::fr_to_be_bytes;
use pso_protocol::nft::{compute_spending_unit_hash, compute_tribute_draft_hash};

// ---------------------------------------------------------------------
// Solidity-wrapper calldata builders.
//
// Each one is a literal Rust transcription of the `abi.encodePacked(...)`
// expression in the matching wrapper in `solidity/PsoProtocol.sol`. If
// either side changes, both must change — and the Foundry mock-call
// tests in `PsoProtocol.t.sol` catch the Solidity-side half of that.
// ---------------------------------------------------------------------

fn slot_u16(v: u16) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[30..32].copy_from_slice(&v.to_be_bytes());
    s
}

fn slot_u64(v: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[24..32].copy_from_slice(&v.to_be_bytes());
    s
}

fn slot_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[12..32].copy_from_slice(addr);
    s
}

/// The `Fr` an address reduces to when packed as a `uint160`-in-`uint256`
/// slot and parsed `Fr::from_be_bytes_mod_order` — the exact conversion
/// the SU-hash precompile applies to the attester / referrer slots.
fn addr_fr(addr: &[u8; 20]) -> Fr {
    Fr::from_be_bytes_mod_order(&slot_address(addr))
}

/// Calldata for `PsoProtocol.computeBindingHash`:
/// `abi.encodePacked(uint256(uint160(sender)), tributeDraftId, chainId)` — 96 bytes.
fn solidity_binding_input(sender: &[u8; 20], tdid: &[u8; 32], chain_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(&slot_address(sender));
    buf.extend_from_slice(tdid);
    buf.extend_from_slice(&slot_u64(chain_id));
    buf
}

/// Calldata for `PsoProtocol.computeTributeDraftHash`:
/// `abi.encodePacked(id, uint256(currency), uint256(base), uint256(atto),`
/// `   <packed bytes32[] suIds>)`.
fn solidity_td_input(
    id: &[u8; 32],
    currency: u16,
    amount_base: u64,
    amount_atto: u64,
    su_ids: &[[u8; 32]],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128 + 32 * su_ids.len());
    buf.extend_from_slice(id);
    buf.extend_from_slice(&slot_u16(currency));
    buf.extend_from_slice(&slot_u64(amount_base));
    buf.extend_from_slice(&slot_u64(amount_atto));
    for su in su_ids {
        buf.extend_from_slice(su);
    }
    buf
}

/// Calldata for `PsoProtocol.computeSpendingUnitHash`:
/// `abi.encodePacked(id, owner, uint256(uint160(attester)),`
/// `   uint256(uint160(referrer)), uint256(wwd), uint256(currency),`
/// `   uint256(base), uint256(atto), uint256(sr.length), <packed sr>,`
/// `   uint256(ar.length), <packed ar>)`.
#[allow(clippy::too_many_arguments)]
fn solidity_su_input(
    id: &[u8; 32],
    owner: &[u8; 32],
    attester: &[u8; 20],
    referrer: &[u8; 20],
    worldwide_day: u64,
    currency: u16,
    amount_base: u64,
    amount_atto: u64,
    sr_fps: &[[u8; 32]],
    ar_fps: &[[u8; 32]],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256 + 64 + 32 * (sr_fps.len() + ar_fps.len()));
    buf.extend_from_slice(id);
    buf.extend_from_slice(owner);
    buf.extend_from_slice(&slot_address(attester));
    buf.extend_from_slice(&slot_address(referrer));
    buf.extend_from_slice(&slot_u64(worldwide_day));
    buf.extend_from_slice(&slot_u16(currency));
    buf.extend_from_slice(&slot_u64(amount_base));
    buf.extend_from_slice(&slot_u64(amount_atto));
    buf.extend_from_slice(&slot_u64(sr_fps.len() as u64));
    for fp in sr_fps {
        buf.extend_from_slice(fp);
    }
    buf.extend_from_slice(&slot_u64(ar_fps.len() as u64));
    for fp in ar_fps {
        buf.extend_from_slice(fp);
    }
    buf
}

// ---------------------------------------------------------------------
// Precompile bodies (option (a)).
//
// Adapted line-for-line from:
//   pso-chain/crates/pso-chain-node/src/precompile/protocol_binding_hash.rs
//   pso-chain/crates/pso-chain-node/src/precompile/protocol_td_hash.rs
//   pso-chain/crates/pso-chain-node/src/precompile/protocol_su_hash.rs
//
// Gas accounting and error-reporting are stripped — we only care about
// the decode-and-call-and-encode pipeline here. Production gas
// behaviour is covered by pso-chain's own unit tests.
// ---------------------------------------------------------------------

mod precompile {
    use super::*;

    const SLOT: usize = 32;

    fn fr_to_be32(value: &Fr) -> [u8; 32] {
        let be = value.into_bigint().to_bytes_be();
        let mut out = [0u8; 32];
        let off = 32 - be.len().min(32);
        out[off..].copy_from_slice(&be[be.len().saturating_sub(32)..]);
        out
    }

    /// `0x0210` — binding hash. Input: 96 bytes `[sender|tdid|chainId]`.
    pub fn binding_hash(input: &[u8]) -> [u8; 32] {
        assert_eq!(input.len(), 96, "binding-hash precompile expects 96 bytes");

        let sender: [u8; 20] = input[12..32].try_into().expect("slice");
        let tdid: [u8; 32] = input[32..64].try_into().expect("slice");

        let chain_id_bytes = &input[64..96];
        assert!(
            chain_id_bytes[..24].iter().all(|&b| b == 0),
            "chainId upper bits must be zero (u64 range)"
        );
        let chain_id = u64::from_be_bytes(chain_id_bytes[24..32].try_into().expect("slice"));

        let digest = compute_binding_hash(&sender, &tdid, chain_id).expect("binding hash");
        fr_to_be32(&digest)
    }

    fn take_u16_strict(slot: &[u8; 32], field: &str) -> u16 {
        assert!(
            slot[..30].iter().all(|&b| b == 0),
            "{field}: upper bits must be zero (u16 range)"
        );
        u16::from_be_bytes(slot[30..32].try_into().expect("slice"))
    }

    fn take_u64_strict(slot: &[u8; 32], field: &str) -> u64 {
        assert!(
            slot[..24].iter().all(|&b| b == 0),
            "{field}: upper bits must be zero (u64 range)"
        );
        u64::from_be_bytes(slot[24..32].try_into().expect("slice"))
    }

    /// `0x0211` — TributeDraft entity hash. Input layout:
    /// `[id|currency|base|atto| su_0 | … | su_{N-1}]`, each slot 32 BE bytes.
    pub fn td_hash(input: &[u8]) -> [u8; 32] {
        const FIXED: usize = 128;
        assert!(
            input.len() >= FIXED,
            "td-hash precompile: input shorter than fixed header"
        );
        assert!(
            input.len().is_multiple_of(SLOT),
            "td-hash precompile: input not slot-aligned"
        );

        let id_slot: [u8; 32] = input[..32].try_into().expect("slice");
        let cur_slot: [u8; 32] = input[32..64].try_into().expect("slice");
        let base_slot: [u8; 32] = input[64..96].try_into().expect("slice");
        let atto_slot: [u8; 32] = input[96..128].try_into().expect("slice");

        let id = Fr::from_be_bytes_mod_order(&id_slot);
        let currency = take_u16_strict(&cur_slot, "currency");
        let amount_base = take_u64_strict(&base_slot, "amountBase");
        let amount_atto = take_u64_strict(&atto_slot, "amountAtto");

        let su_ids: Vec<Fr> = input[FIXED..]
            .chunks_exact(SLOT)
            .map(Fr::from_be_bytes_mod_order)
            .collect();

        let digest = compute_tribute_draft_hash(&id, currency, amount_base, amount_atto, &su_ids)
            .expect("td hash");
        fr_to_be32(&digest)
    }

    /// `0x0212` — SpendingUnit entity hash. Layout:
    /// `[id|owner|attester|referrer|wwd|currency|base|atto| sr_count | sr_0..sr_{M-1} | ar_count | ar_0..ar_{K-1}]`.
    pub fn su_hash(input: &[u8]) -> [u8; 32] {
        const FIXED: usize = 256;
        assert!(
            input.len().is_multiple_of(SLOT),
            "su-hash precompile: input not slot-aligned"
        );
        assert!(
            input.len() >= FIXED + SLOT * 2,
            "su-hash precompile: missing sr_count/ar_count slots"
        );

        let id_slot: [u8; 32] = input[..32].try_into().expect("slice");
        let owner_slot: [u8; 32] = input[32..64].try_into().expect("slice");
        let attester_slot: [u8; 32] = input[64..96].try_into().expect("slice");
        let referrer_slot: [u8; 32] = input[96..128].try_into().expect("slice");
        let wwd_slot: [u8; 32] = input[128..160].try_into().expect("slice");
        let cur_slot: [u8; 32] = input[160..192].try_into().expect("slice");
        let base_slot: [u8; 32] = input[192..224].try_into().expect("slice");
        let atto_slot: [u8; 32] = input[224..256].try_into().expect("slice");

        let id = Fr::from_be_bytes_mod_order(&id_slot);
        let owner = Fr::from_be_bytes_mod_order(&owner_slot);
        let attester = Fr::from_be_bytes_mod_order(&attester_slot);
        let referrer = Fr::from_be_bytes_mod_order(&referrer_slot);
        let worldwide_day = take_u64_strict(&wwd_slot, "worldwideDay");
        let currency = take_u16_strict(&cur_slot, "currency");
        let amount_base = take_u64_strict(&base_slot, "amountBase");
        let amount_atto = take_u64_strict(&atto_slot, "amountAtto");

        let sr_count_slot: [u8; 32] = input[256..288].try_into().expect("slice");
        let sr_count = take_u64_strict(&sr_count_slot, "srCount") as usize;
        let sr_start = 288;
        let sr_end = sr_start + sr_count * SLOT;
        assert!(
            sr_end + SLOT <= input.len(),
            "su-hash precompile: srCount overruns input"
        );
        let sr_fps: Vec<Fr> = input[sr_start..sr_end]
            .chunks_exact(SLOT)
            .map(Fr::from_be_bytes_mod_order)
            .collect();

        let ar_count_slot: [u8; 32] = input[sr_end..sr_end + SLOT].try_into().expect("slice");
        let ar_count = take_u64_strict(&ar_count_slot, "arCount") as usize;
        let ar_start = sr_end + SLOT;
        let ar_end = ar_start + ar_count * SLOT;
        assert_eq!(
            ar_end,
            input.len(),
            "su-hash precompile: arCount mismatch with remaining input"
        );
        let ar_fps: Vec<Fr> = input[ar_start..ar_end]
            .chunks_exact(SLOT)
            .map(Fr::from_be_bytes_mod_order)
            .collect();

        let digest = compute_spending_unit_hash(
            &id,
            &owner,
            &attester,
            &referrer,
            worldwide_day,
            currency,
            amount_base,
            amount_atto,
            &sr_fps,
            &ar_fps,
        )
        .expect("su hash");
        fr_to_be32(&digest)
    }
}

// ---------------------------------------------------------------------
// Fixed vectors. These exist to (a) document the inputs we have
// hand-verified at extraction time, and (b) give a stable check the
// next reader can eyeball without proptest noise.
// ---------------------------------------------------------------------

#[test]
fn binding_hash_fixed_vector_zero() {
    // Exercises precompile 0x0210.
    let sender = [0u8; 20];
    let tdid = [0u8; 32];
    let chain_id = 0u64;

    let rust = fr_to_be_bytes(&compute_binding_hash(&sender, &tdid, chain_id).unwrap());
    let solidity = precompile::binding_hash(&solidity_binding_input(&sender, &tdid, chain_id));
    assert_eq!(rust, solidity);
}

#[test]
fn binding_hash_fixed_vector_dense() {
    // Exercises precompile 0x0210.
    let sender = [
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let tdid = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
        0x32, 0x10,
    ];
    let chain_id = 19_280_501u64;

    let rust = fr_to_be_bytes(&compute_binding_hash(&sender, &tdid, chain_id).unwrap());
    let solidity = precompile::binding_hash(&solidity_binding_input(&sender, &tdid, chain_id));
    assert_eq!(rust, solidity);
}

#[test]
fn td_hash_fixed_vector_empty_su() {
    // Exercises precompile 0x0211 with no SU ids.
    let id_fr = Fr::from(0xdeadu64);
    let id_bytes = fr_to_be_bytes(&id_fr);

    let rust = fr_to_be_bytes(&compute_tribute_draft_hash(&id_fr, 978, 100, 0, &[]).unwrap());
    let solidity = precompile::td_hash(&solidity_td_input(&id_bytes, 978, 100, 0, &[]));
    assert_eq!(rust, solidity);
}

#[test]
fn td_hash_fixed_vector_with_su() {
    // Exercises precompile 0x0211 with several SU ids.
    let id_fr = Fr::from(0xbeefu64);
    let id_bytes = fr_to_be_bytes(&id_fr);
    let su_fr: Vec<Fr> = (1..=4).map(|i: u64| Fr::from(0x1000 + i)).collect();
    let su_bytes: Vec<[u8; 32]> = su_fr.iter().map(fr_to_be_bytes).collect();

    let rust = fr_to_be_bytes(&compute_tribute_draft_hash(&id_fr, 840, 500, 1, &su_fr).unwrap());
    let solidity = precompile::td_hash(&solidity_td_input(&id_bytes, 840, 500, 1, &su_bytes));
    assert_eq!(rust, solidity);
}

#[test]
fn su_hash_fixed_vector_empty_records() {
    // Exercises precompile 0x0212 with no SR/AR fingerprints.
    let id_fr = Fr::from(0xc0deu64);
    let owner_fr = Fr::from(0xf00du64);
    let id_bytes = fr_to_be_bytes(&id_fr);
    let owner_bytes = fr_to_be_bytes(&owner_fr);
    let attester = [0x5au8; 20];
    let referrer = [0x7au8; 20];

    let rust = fr_to_be_bytes(
        &compute_spending_unit_hash(
            &id_fr,
            &owner_fr,
            &addr_fr(&attester),
            &addr_fr(&referrer),
            100,
            978,
            50,
            0,
            &[],
            &[],
        )
        .unwrap(),
    );
    let solidity = precompile::su_hash(&solidity_su_input(
        &id_bytes,
        &owner_bytes,
        &attester,
        &referrer,
        100,
        978,
        50,
        0,
        &[],
        &[],
    ));
    assert_eq!(rust, solidity);
}

#[test]
fn su_hash_fixed_vector_with_records() {
    // Exercises precompile 0x0212 with mixed SR/AR fingerprints.
    let id_fr = Fr::from(0xc0deu64);
    let owner_fr = Fr::from(0xf00du64);
    let id_bytes = fr_to_be_bytes(&id_fr);
    let owner_bytes = fr_to_be_bytes(&owner_fr);

    let attester = [0x5au8; 20];
    let referrer = [0x7au8; 20];
    let sr_fr: Vec<Fr> = (0..3).map(|i: u64| Fr::from(2000 + i)).collect();
    let ar_fr: Vec<Fr> = (0..5).map(|i: u64| Fr::from(3000 + i)).collect();
    let sr_bytes: Vec<[u8; 32]> = sr_fr.iter().map(fr_to_be_bytes).collect();
    let ar_bytes: Vec<[u8; 32]> = ar_fr.iter().map(fr_to_be_bytes).collect();

    let rust = fr_to_be_bytes(
        &compute_spending_unit_hash(
            &id_fr,
            &owner_fr,
            &addr_fr(&attester),
            &addr_fr(&referrer),
            100,
            978,
            50,
            42,
            &sr_fr,
            &ar_fr,
        )
        .unwrap(),
    );
    let solidity = precompile::su_hash(&solidity_su_input(
        &id_bytes,
        &owner_bytes,
        &attester,
        &referrer,
        100,
        978,
        50,
        42,
        &sr_bytes,
        &ar_bytes,
    ));
    assert_eq!(rust, solidity);
}

// ---------------------------------------------------------------------
// Property tests.
//
// Property-based, not just fixed vectors: any byte divergence under any
// shape of input must fail the build. We bound array lengths so cases
// stay cheap (Poseidon2 dominates each absorb) — extremes are covered
// by the fixed vectors plus a dedicated `*_extreme_lengths` test.
// ---------------------------------------------------------------------

const PROPTEST_CASES: u32 = 64;

fn proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: PROPTEST_CASES,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(proptest_config())]

    /// Property: precompile 0x0210 and `compute_binding_hash` agree on
    /// every (sender, tdid, chain_id) triple.
    #[test]
    fn binding_hash_property(
        sender in any::<[u8; 20]>(),
        tdid in any::<[u8; 32]>(),
        chain_id in any::<u64>(),
    ) {
        let rust = fr_to_be_bytes(
            &compute_binding_hash(&sender, &tdid, chain_id).unwrap(),
        );
        let solidity =
            precompile::binding_hash(&solidity_binding_input(&sender, &tdid, chain_id));
        prop_assert_eq!(rust, solidity);
    }

    /// Property: precompile 0x0211 and `compute_tribute_draft_hash` agree
    /// on every (id, currency, base, atto, su_ids[…]) tuple.
    #[test]
    fn td_hash_property(
        id_bytes in any::<[u8; 32]>(),
        currency in any::<u16>(),
        amount_base in any::<u64>(),
        amount_atto in any::<u64>(),
        su_bytes in prop::collection::vec(any::<[u8; 32]>(), 0..=8),
    ) {
        let id_fr = Fr::from_be_bytes_mod_order(&id_bytes);
        let su_fr: Vec<Fr> =
            su_bytes.iter().map(|b| Fr::from_be_bytes_mod_order(b)).collect();

        let rust = fr_to_be_bytes(
            &compute_tribute_draft_hash(&id_fr, currency, amount_base, amount_atto, &su_fr)
                .unwrap(),
        );
        let solidity = precompile::td_hash(&solidity_td_input(
            &id_bytes,
            currency,
            amount_base,
            amount_atto,
            &su_bytes,
        ));
        prop_assert_eq!(rust, solidity);
    }

    /// Property: precompile 0x0212 and `compute_spending_unit_hash` agree
    /// on every (id, owner, wwd, currency, base, atto, sr[…], ar[…]) tuple.
    #[test]
    fn su_hash_property(
        id_bytes in any::<[u8; 32]>(),
        owner_bytes in any::<[u8; 32]>(),
        attester in any::<[u8; 20]>(),
        referrer in any::<[u8; 20]>(),
        worldwide_day in any::<u64>(),
        currency in any::<u16>(),
        amount_base in any::<u64>(),
        amount_atto in any::<u64>(),
        sr_bytes in prop::collection::vec(any::<[u8; 32]>(), 0..=6),
        ar_bytes in prop::collection::vec(any::<[u8; 32]>(), 0..=6),
    ) {
        let id_fr = Fr::from_be_bytes_mod_order(&id_bytes);
        let owner_fr = Fr::from_be_bytes_mod_order(&owner_bytes);
        let sr_fr: Vec<Fr> =
            sr_bytes.iter().map(|b| Fr::from_be_bytes_mod_order(b)).collect();
        let ar_fr: Vec<Fr> =
            ar_bytes.iter().map(|b| Fr::from_be_bytes_mod_order(b)).collect();

        let rust = fr_to_be_bytes(
            &compute_spending_unit_hash(
                &id_fr,
                &owner_fr,
                &addr_fr(&attester),
                &addr_fr(&referrer),
                worldwide_day,
                currency,
                amount_base,
                amount_atto,
                &sr_fr,
                &ar_fr,
            )
            .unwrap(),
        );
        let solidity = precompile::su_hash(&solidity_su_input(
            &id_bytes,
            &owner_bytes,
            &attester,
            &referrer,
            worldwide_day,
            currency,
            amount_base,
            amount_atto,
            &sr_bytes,
            &ar_bytes,
        ));
        prop_assert_eq!(rust, solidity);
    }
}

// ---------------------------------------------------------------------
// Boundary tests — extreme lengths the proptest config bounds don't hit.
// ---------------------------------------------------------------------

#[test]
fn td_hash_extreme_su_count() {
    // Exercises precompile 0x0211 at a non-trivial vector length.
    let id_fr = Fr::from(1u64);
    let id_bytes = fr_to_be_bytes(&id_fr);
    let su_fr: Vec<Fr> = (0..64).map(|i: u64| Fr::from(7919 + i)).collect();
    let su_bytes: Vec<[u8; 32]> = su_fr.iter().map(fr_to_be_bytes).collect();

    let rust = fr_to_be_bytes(&compute_tribute_draft_hash(&id_fr, 840, 1, 1, &su_fr).unwrap());
    let solidity = precompile::td_hash(&solidity_td_input(&id_bytes, 840, 1, 1, &su_bytes));
    assert_eq!(rust, solidity);
}

#[test]
fn su_hash_extreme_record_counts() {
    // Exercises precompile 0x0212 with asymmetric, larger record vectors.
    let id_fr = Fr::from(1u64);
    let owner_fr = Fr::from(2u64);
    let id_bytes = fr_to_be_bytes(&id_fr);
    let owner_bytes = fr_to_be_bytes(&owner_fr);
    let attester = [0xffu8; 20];
    let referrer = [0x00u8; 20];
    let sr_fr: Vec<Fr> = (0..32).map(|i: u64| Fr::from(1000 + i)).collect();
    let ar_fr: Vec<Fr> = (0..16).map(|i: u64| Fr::from(5000 + i)).collect();
    let sr_bytes: Vec<[u8; 32]> = sr_fr.iter().map(fr_to_be_bytes).collect();
    let ar_bytes: Vec<[u8; 32]> = ar_fr.iter().map(fr_to_be_bytes).collect();

    let rust = fr_to_be_bytes(
        &compute_spending_unit_hash(
            &id_fr,
            &owner_fr,
            &addr_fr(&attester),
            &addr_fr(&referrer),
            u64::MAX,
            u16::MAX,
            u64::MAX,
            u64::MAX,
            &sr_fr,
            &ar_fr,
        )
        .unwrap(),
    );
    let solidity = precompile::su_hash(&solidity_su_input(
        &id_bytes,
        &owner_bytes,
        &attester,
        &referrer,
        u64::MAX,
        u16::MAX,
        u64::MAX,
        u64::MAX,
        &sr_bytes,
        &ar_bytes,
    ));
    assert_eq!(rust, solidity);
}
