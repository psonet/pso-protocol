//! Cross-side equality smoke test.
//!
//! For every precompile-bound formula, this test asserts that the Rust
//! implementation in `pso-protocol` and the Solidity wrapper invoking the
//! corresponding precompile return the **same 32 bytes** for a randomized
//! input. Drift between the two would silently break proof verification
//! across the off-chain ↔ on-chain boundary, which is precisely what the
//! `pso-protocol` extraction exists to prevent.
//!
//! The current phase-1 scaffold only checks that the test harness wires up
//! against the Rust side. Real Rust-vs-Solidity comparisons land once the
//! per-formula migrations (phases 2–4) ship a revm host that exposes the
//! pso-protocol precompiles at `0x0210..0x0214`.

#[test]
fn rust_side_hash_modules_link() {
    use pso_protocol::hash::ProtocolHasher;
    use pso_protocol::Fr;

    let h = ProtocolHasher::new()
        .absorb(Fr::from(1u64))
        .unwrap()
        .absorb_u64(2)
        .unwrap()
        .finalize();
    assert_ne!(h, Fr::from(0u64));
}
