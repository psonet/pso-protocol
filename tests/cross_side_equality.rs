//! Cross-side equality smoke test.
//!
//! For every precompile-bound formula, this test asserts that the Rust
//! implementation in `pso-protocol` and the Solidity wrapper invoking
//! the corresponding precompile return the **same 32 bytes** for a
//! randomized input. Drift between the two would silently break proof
//! verification across the off-chain ↔ on-chain boundary, which is
//! precisely what the `pso-protocol` extraction exists to prevent.
//!
//! Today this is a **Rust-only** consistency suite: it confirms that
//! the public surface compiles, that round-tripping `Fr ↔ bytes` is
//! lossless, and that the same input hashed twice produces identical
//! bytes. Real Rust-vs-Solidity comparisons (spawning a revm host that
//! exposes precompiles `0x0210..0x0212`) land once pso-chain registers
//! those addresses — see `docs/issues/pso-protocol-extraction.md`,
//! phase 6.

use pso_protocol::binding::compute_binding_hash;
use pso_protocol::fr::{fr_from_be_bytes, fr_to_be_bytes};
use pso_protocol::hash::ProtocolHasher;
use pso_protocol::Fr;

#[test]
fn protocol_hasher_links() {
    let h = ProtocolHasher::new(Fr::from(1u64))
        .absorb_u64(2)
        .unwrap()
        .finalize();
    assert_ne!(h, Fr::from(0u64));
}

#[test]
fn binding_hash_round_trip_is_byte_stable() {
    let sender = [0xab; 20];
    let tdid = [0xcd; 32];
    let h = compute_binding_hash(&sender, &tdid, 1).unwrap();

    let bytes = fr_to_be_bytes(&h);
    let recovered = fr_from_be_bytes(&bytes);
    assert_eq!(h, recovered, "Fr ↔ bytes round trip lost data");
}

#[test]
fn binding_hash_is_deterministic() {
    let sender = [0x01; 20];
    let tdid = [0x02; 32];
    let a = compute_binding_hash(&sender, &tdid, 1).unwrap();
    let b = compute_binding_hash(&sender, &tdid, 1).unwrap();
    assert_eq!(a, b);
}
