//! Incremental Merkle Tree (IMT) hashing for the TributeDraft commitment
//! windows.
//!
//! A binary, append-only Poseidon2 Merkle tree of fixed depth
//! [`TREE_DEPTH`] (one tree per open commitment window). This module is the
//! **single canonical implementation** of the window tree's hashing and
//! inclusion semantics — the one inclusion-proof primitive — shared by:
//!
//! - the on-chain stateless frontier-insert precompile (`0x0204`), which
//!   appends a leaf and returns the changed frontier slot + new root
//!   ([`insert`]);
//! - off-chain root reconstruction / inclusion-proof building (the indexer,
//!   the wallet) and the in-circuit membership check
//!   ([`root_from_inclusion_path`]).
//!
//! ## Hashing
//!
//! All hashing is Poseidon2 over BN254 `Fr`. A parent node is
//! `Poseidon2(left, right)` ([`node_hash`]). The zero ladder is seeded by
//! the caller-supplied **empty-leaf** value (`zero[0] = empty_leaf`,
//! `zero[i] = Poseidon2(zero[i-1], zero[i-1])`), so this module stays
//! agnostic of the leaf formula (the TD leaf, `0x0213`): the commitment
//! window seeds it with `Poseidon2(TAG_TD_LEAF, 0, 0, 0)`.
//!
//! `Fr`↔bytes encoding is the caller's concern; the Solidity boundary uses
//! big-endian `bytes32`.
//!
//! ## Frontier append
//!
//! Each append changes **exactly one** frontier slot — the lowest level
//! where the new leaf index has a zero bit (the new "filled left subtree"
//! waiting for its right sibling). Higher levels only recompute the root
//! against the zero ladder, and lower (set-bit) levels merge with the
//! existing frontier (always written by an earlier append before it is
//! read). This matches `CommitmentWindowBase`, which writes a single
//! `_frontier[changedLevel]` per insert.

use ark_bn254::Fr;

use crate::error::ProtocolError;
use crate::hash::poseidon2;

/// Commitment-window tree depth. Matches `CommitmentWindowBase.TREE_DEPTH`
/// and the in-circuit membership-path length. Fixed because the on-chain
/// frontier is a fixed-size storage array; changing it is a coordinated
/// migration with the prover/verifier (and a major-version bump).
pub const TREE_DEPTH: usize = 26;

/// Parent node hash: `Poseidon2(left, right)`.
pub fn node_hash(left: Fr, right: Fr) -> Result<Fr, ProtocolError> {
    poseidon2(left, right)
}

/// Build the zero-subtree ladder for a tree of `depth` from its
/// `empty_leaf` value: `zeros[0] = empty_leaf`,
/// `zeros[i] = Poseidon2(zeros[i-1], zeros[i-1])`. The returned vector has
/// `depth + 1` entries; `zeros[level]` is the root of an all-empty subtree
/// of height `level`, and `zeros[depth]` is the empty-tree root.
pub fn zero_ladder(empty_leaf: Fr, depth: usize) -> Result<Vec<Fr>, ProtocolError> {
    let mut zeros = Vec::with_capacity(depth + 1);
    zeros.push(empty_leaf);
    for level in 1..=depth {
        zeros.push(node_hash(zeros[level - 1], zeros[level - 1])?);
    }
    Ok(zeros)
}

/// Root of the empty depth-`depth` tree for the given `empty_leaf`.
///
/// The commitment window uses this for `CommitmentWindowBase._emptyTreeRoot`
/// with `depth = TREE_DEPTH` and `empty_leaf = Poseidon2(TAG_TD_LEAF, 0,0,0)`.
pub fn empty_root(empty_leaf: Fr, depth: usize) -> Result<Fr, ProtocolError> {
    Ok(zero_ladder(empty_leaf, depth)?[depth])
}

/// Result of a single frontier append — mirrors the `0x0204` precompile
/// output `(changedLevel, newSubtree, newRoot)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insert {
    /// The single frontier level whose stored subtree changes.
    pub changed_level: usize,
    /// The new value to store at `frontier[changed_level]`.
    pub new_subtree: Fr,
    /// The tree root after the append.
    pub new_root: Fr,
}

/// Append `leaf` at position `next_index` to a tree described by its
/// `frontier` (filled left-subtree hash per level, `frontier.len() == depth`)
/// and its `zeros` ladder (`zeros.len() == depth + 1`, e.g. from
/// [`zero_ladder`]). Returns the single changed frontier slot and the new
/// root.
///
/// Walking up from the leaf, at each level the node is a left child
/// (sibling = `zeros[level]`) or a right child (sibling = `frontier[level]`)
/// per `next_index`'s bit at that level. The changed slot is the lowest
/// zero-bit level.
pub fn insert(
    frontier: &[Fr],
    next_index: u64,
    leaf: Fr,
    zeros: &[Fr],
) -> Result<Insert, ProtocolError> {
    let depth = frontier.len();
    if zeros.len() != depth + 1 {
        return Err(ProtocolError::Poseidon(format!(
            "imt::insert: zeros.len() ({}) must be frontier.len()+1 ({})",
            zeros.len(),
            depth + 1
        )));
    }
    if next_index >= (1u64 << depth) {
        return Err(ProtocolError::Poseidon(format!(
            "imt::insert: next_index {next_index} overflows depth-{depth} tree"
        )));
    }

    let mut current = leaf;
    let mut index = next_index;
    let mut changed: Option<(usize, Fr)> = None;
    for level in 0..depth {
        if index & 1 == 0 {
            // Left child: the accumulated subtree becomes the new frontier
            // entry the first time we hit a zero bit; pair with the zero
            // ladder for the (empty) right side.
            if changed.is_none() {
                changed = Some((level, current));
            }
            current = node_hash(current, zeros[level])?;
        } else {
            // Right child: merge with the waiting left sibling.
            current = node_hash(frontier[level], current)?;
        }
        index >>= 1;
    }

    let (changed_level, new_subtree) = match changed {
        Some(c) => c,
        None => {
            // The tree-completing append (`next_index == 2^depth - 1`): the
            // leaf is a right child all the way up, so no new left subtree
            // waits and the frontier is never read again (the next append
            // would be `WindowFull`). Report the top slot written back
            // unchanged, so the contract's single-slot write is a no-op and
            // `changed_level` stays in range.
            let top = depth - 1;
            (top, frontier[top])
        }
    };
    Ok(Insert {
        changed_level,
        new_subtree,
        new_root: current,
    })
}

/// Recompute the tree root from an inclusion path: the `leaf`, its
/// `leaf_index`, and the sibling hash at each level bottom-up
/// (`siblings.len()` = tree depth). This is **the** inclusion-proof
/// primitive — the index bits select the left/right side at each level, so
/// no per-element side flag is stored.
pub fn root_from_inclusion_path(
    leaf: Fr,
    leaf_index: u64,
    siblings: &[Fr],
) -> Result<Fr, ProtocolError> {
    let depth = siblings.len();
    if leaf_index >= (1u64 << depth) {
        return Err(ProtocolError::Poseidon(format!(
            "imt::root_from_inclusion_path: leaf_index {leaf_index} overflows depth-{depth} tree"
        )));
    }
    let mut current = leaf;
    let mut index = leaf_index;
    for sibling in siblings {
        current = if index & 1 == 0 {
            node_hash(current, *sibling)?
        } else {
            node_hash(*sibling, current)?
        };
        index >>= 1;
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fr(n: u64) -> Fr {
        Fr::from(n)
    }

    /// Ground-truth root: a full depth-`depth` tree whose first
    /// `leaves.len()` positions hold the leaves and the rest hold the empty
    /// leaf, folded pairwise to the root.
    fn naive_root(leaves: &[Fr], depth: usize, zeros: &[Fr]) -> Fr {
        let width = 1usize << depth;
        let mut level: Vec<Fr> = (0..width)
            .map(|i| leaves.get(i).copied().unwrap_or(zeros[0]))
            .collect();
        for _ in 0..depth {
            level = level
                .chunks_exact(2)
                .map(|p| node_hash(p[0], p[1]).unwrap())
                .collect();
        }
        level[0]
    }

    #[test]
    fn empty_root_matches_naive_empty_tree() {
        let empty_leaf = fr(0xE1);
        for depth in [1usize, 3, 8] {
            let zeros = zero_ladder(empty_leaf, depth).unwrap();
            let naive = naive_root(&[], depth, &zeros);
            assert_eq!(
                empty_root(empty_leaf, depth).unwrap(),
                naive,
                "depth={depth}"
            );
            assert_eq!(zeros[depth], naive);
        }
    }

    #[test]
    fn incremental_inserts_match_full_tree() {
        let empty_leaf = fr(0xE1);
        let depth = 3usize; // 8 leaves
        let zeros = zero_ladder(empty_leaf, depth).unwrap();
        let mut frontier = vec![fr(0); depth];

        let mut inserted: Vec<Fr> = Vec::new();
        for i in 0..(1u64 << depth) {
            let leaf = fr(1000 + i);
            let ins = insert(&frontier, i, leaf, &zeros).unwrap();
            frontier[ins.changed_level] = ins.new_subtree;
            inserted.push(leaf);
            assert_eq!(
                ins.new_root,
                naive_root(&inserted, depth, &zeros),
                "root mismatch after inserting leaf {i}"
            );
        }
    }

    #[test]
    fn insert_changes_exactly_the_lowest_zero_bit_level() {
        let empty_leaf = fr(0xE1);
        let depth = 4usize;
        let zeros = zero_ladder(empty_leaf, depth).unwrap();
        let mut frontier = vec![fr(0); depth];
        let last = (1u64 << depth) - 1;
        for i in 0..(1u64 << depth) {
            let ins = insert(&frontier, i, fr(7000 + i), &zeros).unwrap();
            // Lowest zero-bit level = count of trailing one bits; the
            // tree-completing append (all ones) has none and reports `top`.
            let expected = if i == last {
                depth - 1
            } else {
                i.trailing_ones() as usize
            };
            assert_eq!(ins.changed_level, expected, "i={i}");
            frontier[ins.changed_level] = ins.new_subtree;
        }
    }

    #[test]
    fn inclusion_path_reproduces_root() {
        // Build a full depth-3 tree, then check each leaf's index-derived
        // path reproduces the root via `root_from_inclusion_path`.
        let empty_leaf = fr(0xE1);
        let depth = 3usize;
        let zeros = zero_ladder(empty_leaf, depth).unwrap();
        let leaves: Vec<Fr> = (0..(1u64 << depth)).map(|i| fr(2000 + i)).collect();
        let root = naive_root(&leaves, depth, &zeros);

        // Level-0 = leaves; build up, recording siblings per leaf.
        let mut levels: Vec<Vec<Fr>> = vec![leaves.clone()];
        for d in 0..depth {
            let next: Vec<Fr> = levels[d]
                .chunks_exact(2)
                .map(|p| node_hash(p[0], p[1]).unwrap())
                .collect();
            levels.push(next);
        }
        for (leaf_index, &leaf) in leaves.iter().enumerate() {
            let mut node = leaf_index;
            let siblings: Vec<Fr> = (0..depth)
                .map(|d| {
                    let sib = node ^ 1;
                    node >>= 1;
                    levels[d][sib]
                })
                .collect();
            assert_eq!(
                root_from_inclusion_path(leaf, leaf_index as u64, &siblings).unwrap(),
                root,
                "inclusion path failed for leaf_index={leaf_index}"
            );
        }
    }

    #[test]
    fn out_of_range_index_errors() {
        let zeros = zero_ladder(fr(1), 3).unwrap();
        let frontier = [fr(0); 3];
        assert!(insert(&frontier, 8, fr(9), &zeros).is_err()); // 8 == 2^3
        assert!(root_from_inclusion_path(fr(9), 8, &[fr(0); 3]).is_err());
    }
}
