//! Single-shot `Poseidon5` over BN254 Fr.
//!
//! Used exclusively by the ownership formula (`ownership.rs`), which
//! takes five field elements — the four 128-bit limbs of a secp256k1
//! public-key point plus a nonce — and hashes them into a single owner
//! commitment. The ZK circuit asserts the same hash inside the proof.
//!
//! This is **not** wrapped by `ProtocolHasher`: ownership is not an
//! iterated structure, and binding it to a single-shot helper makes the
//! formula's wire shape impossible to confuse with the entity hashes.

use ark_bn254::Fr;
use pso_poseidon::PoseidonHasher;

use crate::ProtocolError;

/// Single-shot Poseidon5 over five `Fr` values.
pub fn poseidon5(a: Fr, b: Fr, c: Fr, d: Fr, e: Fr) -> Result<Fr, ProtocolError> {
    let mut poseidon = pso_poseidon::Poseidon::<Fr>::new_circom(5)
        .map_err(|err| ProtocolError::Poseidon(format!("new_circom(5): {err}")))?;
    poseidon
        .hash(&[a, b, c, d, e])
        .map_err(|err| ProtocolError::Poseidon(format!("hash: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon5_deterministic() {
        let inputs = (
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
        );
        let a = poseidon5(inputs.0, inputs.1, inputs.2, inputs.3, inputs.4).unwrap();
        let b = poseidon5(inputs.0, inputs.1, inputs.2, inputs.3, inputs.4).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn poseidon5_order_sensitive() {
        let a = poseidon5(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
        )
        .unwrap();
        let b = poseidon5(
            Fr::from(5u64),
            Fr::from(4u64),
            Fr::from(3u64),
            Fr::from(2u64),
            Fr::from(1u64),
        )
        .unwrap();
        assert_ne!(a, b);
    }
}
