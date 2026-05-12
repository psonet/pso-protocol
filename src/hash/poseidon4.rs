//! Single-shot `Poseidon4` over BN254 Fr.
//!
//! Used by the binding hash (`binding.rs`), which combines four field
//! elements — `sender_field`, two 128-bit limbs of `tribute_draft_id`,
//! and `chain_id` — into a single commitment that the on-chain
//! `TributeDraft` contract recomputes to anchor the ZK proof.
//!
//! Like `poseidon5`, this is **not** the iterated Poseidon2 of
//! [`ProtocolHasher`]. The binding formula was designed before the
//! iterated pattern existed and has been fixed by the on-chain wire
//! format ever since — changing the arity is consensus-breaking.

use ark_bn254::Fr;
use pso_poseidon::PoseidonHasher;

use crate::ProtocolError;

/// Single-shot Poseidon4 over four `Fr` values.
pub fn poseidon4(a: Fr, b: Fr, c: Fr, d: Fr) -> Result<Fr, ProtocolError> {
    let mut poseidon = pso_poseidon::Poseidon::<Fr>::new_circom(4)
        .map_err(|err| ProtocolError::Poseidon(format!("new_circom(4): {err}")))?;
    poseidon
        .hash(&[a, b, c, d])
        .map_err(|err| ProtocolError::Poseidon(format!("hash: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon4_deterministic() {
        let a = poseidon4(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        )
        .unwrap();
        let b = poseidon4(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn poseidon4_order_sensitive() {
        let a = poseidon4(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        )
        .unwrap();
        let b = poseidon4(
            Fr::from(4u64),
            Fr::from(3u64),
            Fr::from(2u64),
            Fr::from(1u64),
        )
        .unwrap();
        assert_ne!(a, b);
    }
}
