//! Single-shot `Poseidon3` over BN254 Fr.
//!
//! Used by the Grumpkin ownership formula in `ownership.rs`, which
//! takes three field elements -- the two Grumpkin public-key
//! coordinates plus a nonce -- and hashes them into a single owner
//! commitment. The ZK circuit asserts the same hash inside the proof.

use ark_bn254::Fr;
use pso_poseidon::PoseidonHasher;

use crate::ProtocolError;

/// Single-shot Poseidon3 over three `Fr` values.
pub fn poseidon3(a: Fr, b: Fr, c: Fr) -> Result<Fr, ProtocolError> {
    let mut poseidon = pso_poseidon::Poseidon::<Fr>::new_circom(3)
        .map_err(|err| ProtocolError::Poseidon(format!("new_circom(3): {err}")))?;
    poseidon
        .hash(&[a, b, c])
        .map_err(|err| ProtocolError::Poseidon(format!("hash: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon3_deterministic() {
        let a = poseidon3(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)).unwrap();
        let b = poseidon3(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn poseidon3_order_sensitive() {
        let a = poseidon3(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)).unwrap();
        let b = poseidon3(Fr::from(3u64), Fr::from(2u64), Fr::from(1u64)).unwrap();
        assert_ne!(a, b);
    }
}
