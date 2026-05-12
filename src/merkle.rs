//! Sparse-Merkle path types and root computation.
//!
//! Mirrors `pso_zk_core::witness::compute_merkle_root` and the
//! `MerklePathElement` / `MerklePathElementIndex` types from
//! `pso-zk-core`. Node hashes are 32 raw bytes (instead of
//! `GenericArray<u8, U32>`) — the encoding is **little-endian**, as
//! expected by the ZK circuit's witness format.
//!
//! ## Bound to the ZK circuit
//!
//! Both the path-element layout and the iterated-Poseidon2 root
//! computation are fixed by the Noir circuit source. Changing either
//! requires recompiling the circuit and updating the canonical
//! descriptor.

use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::error::ProtocolError;
use crate::hash::poseidon2;

/// Must match the circuit's fixed Merkle tree depth.
pub const SPARSE_MERKLE_PATH_DEPTH: usize = 8;

/// Position of a node within a Merkle path level.
///
/// Uses `repr(u8)` for compact serialization. `Skip` pads paths
/// shorter than [`SPARSE_MERKLE_PATH_DEPTH`].
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u8)]
pub enum MerklePathElementIndex {
    /// Skip this level (padding for variable-depth trees).
    Skip = 0,
    /// Current node is the left child; sibling is on the right.
    Left = 1,
    /// Current node is the right child; sibling is on the left.
    Right = 2,
}

/// One level of a Merkle inclusion path.
///
/// `node_hash` is the **little-endian** 32-byte encoding of the sibling's
/// Fr value, matching the circuit's witness format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePathElement {
    /// Sibling hash (LE-encoded Fr).
    pub node_hash: [u8; 32],
    /// Sibling position relative to the current node.
    pub index: MerklePathElementIndex,
}

/// Compute the Merkle root from a leaf hash and a path of siblings.
///
/// Processes all levels up to `depth`, matching circuit behavior:
/// - Real path elements use their sibling hash and index.
/// - Padded levels (beyond `merkle_path.len()`) use sibling=0,
///   current-on-right.
pub fn compute_merkle_root(
    entity_hash: &Fr,
    merkle_path: &[MerklePathElement],
    depth: usize,
) -> Result<Fr, ProtocolError> {
    let mut current_hash = *entity_hash;

    for i in 0..depth {
        let (sibling, is_left) = if i < merkle_path.len() {
            let element = &merkle_path[i];
            let sibling = Fr::from_le_bytes_mod_order(&element.node_hash);
            let is_left = match element.index {
                // Right = sibling on right, current on left → is_left = true.
                MerklePathElementIndex::Right => true,
                // Left = sibling on left, current on right → is_left = false.
                MerklePathElementIndex::Left => false,
                // Skip = padding (sibling on left).
                MerklePathElementIndex::Skip => false,
            };
            (sibling, is_left)
        } else {
            // Padded level: sibling = 0, current on right.
            (Fr::from(0u64), false)
        };

        let (left, right) = if is_left {
            (current_hash, sibling)
        } else {
            (sibling, current_hash)
        };

        current_hash = poseidon2(left, right)?;
    }

    Ok(current_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{BigInteger, PrimeField};
    use pso_poseidon::PoseidonHasher;

    /// Inline replica of the original `pso_zk_core::witness::compute_merkle_root`.
    fn original_inline(entity_hash: &Fr, merkle_path: &[MerklePathElement], depth: usize) -> Fr {
        let mut poseidon = pso_poseidon::Poseidon::<Fr>::new_circom(2).unwrap();
        let mut current_hash = *entity_hash;
        for i in 0..depth {
            let (node_hash, is_left) = if i < merkle_path.len() {
                let element = &merkle_path[i];
                let hash = Fr::from_le_bytes_mod_order(&element.node_hash);
                let is_left = match element.index {
                    MerklePathElementIndex::Right => true,
                    MerklePathElementIndex::Left => false,
                    MerklePathElementIndex::Skip => false,
                };
                (hash, is_left)
            } else {
                (Fr::from(0u64), false)
            };
            let (left, right) = if is_left {
                (current_hash, node_hash)
            } else {
                (node_hash, current_hash)
            };
            current_hash = poseidon.hash(&[left, right]).unwrap();
        }
        current_hash
    }

    fn fr_to_le(value: Fr) -> [u8; 32] {
        let le = value.into_bigint().to_bytes_le();
        let mut out = [0u8; 32];
        out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
        out
    }

    #[test]
    fn index_repr_values_match_original() {
        assert_eq!(MerklePathElementIndex::Skip as u8, 0);
        assert_eq!(MerklePathElementIndex::Left as u8, 1);
        assert_eq!(MerklePathElementIndex::Right as u8, 2);
    }

    #[test]
    fn index_ordering() {
        assert!(MerklePathElementIndex::Skip < MerklePathElementIndex::Left);
        assert!(MerklePathElementIndex::Left < MerklePathElementIndex::Right);
    }

    #[test]
    fn deterministic() {
        let leaf = Fr::from(0xdeadu64);
        let path = vec![MerklePathElement {
            node_hash: fr_to_le(Fr::from(0xb0bau64)),
            index: MerklePathElementIndex::Left,
        }];
        let a = compute_merkle_root(&leaf, &path, SPARSE_MERKLE_PATH_DEPTH).unwrap();
        let b = compute_merkle_root(&leaf, &path, SPARSE_MERKLE_PATH_DEPTH).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn parity_empty_path() {
        let leaf = Fr::from(0xcafeu64);
        let path: Vec<MerklePathElement> = vec![];
        let new = compute_merkle_root(&leaf, &path, SPARSE_MERKLE_PATH_DEPTH).unwrap();
        let old = original_inline(&leaf, &path, SPARSE_MERKLE_PATH_DEPTH);
        assert_eq!(new, old);
    }

    #[test]
    fn parity_mixed_left_right_skip() {
        let leaf = Fr::from(0xfaceu64);
        let path = vec![
            MerklePathElement {
                node_hash: fr_to_le(Fr::from(1u64)),
                index: MerklePathElementIndex::Left,
            },
            MerklePathElement {
                node_hash: fr_to_le(Fr::from(2u64)),
                index: MerklePathElementIndex::Right,
            },
            MerklePathElement {
                node_hash: fr_to_le(Fr::from(3u64)),
                index: MerklePathElementIndex::Skip,
            },
            MerklePathElement {
                node_hash: fr_to_le(Fr::from(4u64)),
                index: MerklePathElementIndex::Left,
            },
        ];
        let new = compute_merkle_root(&leaf, &path, SPARSE_MERKLE_PATH_DEPTH).unwrap();
        let old = original_inline(&leaf, &path, SPARSE_MERKLE_PATH_DEPTH);
        assert_eq!(new, old);
    }

    #[test]
    fn different_indices_give_different_roots() {
        let leaf = Fr::from(7u64);
        let sibling_bytes = fr_to_le(Fr::from(99u64));
        let path_left = vec![MerklePathElement {
            node_hash: sibling_bytes,
            index: MerklePathElementIndex::Left,
        }];
        let path_right = vec![MerklePathElement {
            node_hash: sibling_bytes,
            index: MerklePathElementIndex::Right,
        }];
        let root_left = compute_merkle_root(&leaf, &path_left, SPARSE_MERKLE_PATH_DEPTH).unwrap();
        let root_right = compute_merkle_root(&leaf, &path_right, SPARSE_MERKLE_PATH_DEPTH).unwrap();
        assert_ne!(root_left, root_right);
    }

    #[test]
    fn padded_path_matches_explicit_skip_padding() {
        // Padding beyond `merkle_path.len()` and using explicit `Skip`
        // elements at the same positions must produce the same root.
        let leaf = Fr::from(123u64);

        let short = vec![MerklePathElement {
            node_hash: fr_to_le(Fr::from(42u64)),
            index: MerklePathElementIndex::Left,
        }];
        let mut padded = short.clone();
        for _ in 1..SPARSE_MERKLE_PATH_DEPTH {
            padded.push(MerklePathElement {
                node_hash: [0u8; 32],
                index: MerklePathElementIndex::Skip,
            });
        }

        let root_short = compute_merkle_root(&leaf, &short, SPARSE_MERKLE_PATH_DEPTH).unwrap();
        let root_padded = compute_merkle_root(&leaf, &padded, SPARSE_MERKLE_PATH_DEPTH).unwrap();
        assert_eq!(root_short, root_padded);
    }
}
