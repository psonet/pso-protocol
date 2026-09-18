//! Cross-implementation vectors for [`Suite::binding`].
//!
//! The binding is a consensus formula: the L2 computes it when it builds a
//! witness, and the verifying chain recomputes it from its own copy of
//! `(sender, draft_id, host_chain_id, l2_chain_id)` and compares the result
//! against public word 2. If the two preimages differ by so much as an element,
//! every proof this L2 submits is rejected, and nothing in either repository
//! fails first.
//!
//! So the expected values below are not this implementation's own output. They
//! were produced by the L1 reference, `outbe-l2-claims`'
//! `claims::tribute::binding`, and pasted here. A determinism test cannot catch
//! a drift that moves both sides at once; these can, because regenerating them
//! means going to the other implementation and asking it again.
//!
//! Regenerate only when the two sides have agreed to change the formula, and
//! record what changed in the history rather than editing a digit.

use pso_protocol::suite::Suite;
use pso_protocol::PsoV1;

use ark_ff::{BigInteger, PrimeField};

/// The vectors' fixed sender: 20 bytes of `0x11`.
const SENDER: [u8; 20] = [0x11; 20];

/// The vectors' fixed draft id: bytes `0x00..=0x1f` big-endian, so the two
/// 128-bit limbs differ and a swapped limb order cannot pass by symmetry.
fn draft_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = i as u8;
    }
    id
}

fn binding_hex(host_chain_id: u64, l2_chain_id: u64) -> String {
    let field = PsoV1::binding(&SENDER, &draft_id(), host_chain_id, l2_chain_id)
        .expect("the binding is defined for canonical inputs");
    field
        .into_bigint()
        .to_bytes_be()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Two host/L2 pairs, so a bug that folds one id twice or drops one is visible:
/// no pair is a permutation of the other and neither shares a value.
#[test]
fn binding_matches_the_l1_reference() {
    assert_eq!(
        binding_hex(1, 19_280_501),
        "059205fe287536d2d15c076791a42f8f68f97da002c598c4571023a229339d16",
    );
    assert_eq!(
        binding_hex(424_242, 57_005),
        "214605370f7e766f3029f77d29f9095bf92834caf03a16b789b055449f11e3c6",
    );
}

/// The two ids occupy distinct positions. Were either folded in the other's
/// place, or one dropped, swapping them would leave the digest unchanged.
#[test]
fn the_two_chain_ids_are_not_interchangeable() {
    assert_ne!(binding_hex(1, 19_280_501), binding_hex(19_280_501, 1));
}

/// A submission that never leaves this L2 passes the same id twice. That is a
/// legitimate input, not a degenerate one, and it must still differ from the
/// cross-chain digests above.
#[test]
fn a_same_chain_submission_is_its_own_binding() {
    let same = binding_hex(19_280_501, 19_280_501);
    assert_ne!(same, binding_hex(1, 19_280_501));
    assert_ne!(same, binding_hex(19_280_501, 1));
}
