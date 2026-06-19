//! Incremental Merkle Tree (IMT) — suite-generic inclusion-tree logic.
//!
//! [`Imt`] is a binary, append-only Merkle tree whose node hash is
//! `S::Hash([left, right])` (Poseidon2 for `PsoV1`). It is generic over the
//! suite: only the field + hash are used, no curve/signature. The empty leaf is
//! the field zero (untagged). [`InclusionPath`] is one membership proof (leaf
//! index + sibling hashes) that resolves a root and yields the in-circuit
//! direction bits.
//!
//! This mirrors the on-chain commitment tree (`CommitmentWindowBase` in
//! pso-chain-research): same shape, same `Poseidon2(left, right)` node hash,
//! same `empty_leaf = 0`, and the leaf stored at each position is the entity
//! hash directly. The depth is a caller parameter (the canonical commitment
//! tree fixes it at 32).

use ark_ff::Zero;

use crate::error::Error;
use crate::primitive::hash::FieldHasher;
use crate::suite::Suite;

/// Result of a single frontier append — mirrors the on-chain `0x0204`
/// precompile output `(changedLevel, newSubtree, newRoot)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Append<F> {
    /// The single frontier level whose stored subtree changes.
    pub changed_level: usize,
    /// The new value to store at `frontier[changed_level]`.
    pub new_subtree: F,
    /// The tree root after the append operation.
    pub new_root: F,
}

/// A binary, append-only incremental Merkle tree over `S`'s field + hash
/// (frontier-based, so O(depth) state).
pub struct Imt<S: Suite> {
    depth: usize,
    /// Zero-subtree ladder, `depth + 1` entries.
    zeros: Vec<S::Field>,
    /// Filled left-subtree hash per level, `depth` entries.
    frontier: Vec<S::Field>,
    next_index: u64,
    root: S::Field,
}

impl<S: Suite> Imt<S> {
    /// Parent node hash: `Hash([left, right])` (Poseidon2 for `PsoV1`).
    pub fn node_hash(left: S::Field, right: S::Field) -> Result<S::Field, Error> {
        S::Hash::hash(&[left, right])
    }

    /// Build the zero-subtree ladder: `zeros[0] = empty_leaf`,
    /// `zeros[i] = Hash([zeros[i-1], zeros[i-1]])`. `zeros[level]` is the root
    /// of an all-empty subtree of height `level`. Has `depth + 1` entries.
    pub fn zero_ladder(empty_leaf: S::Field, depth: usize) -> Result<Vec<S::Field>, Error> {
        let mut zeros = Vec::with_capacity(depth + 1);
        zeros.push(empty_leaf);
        for level in 1..=depth {
            zeros.push(Self::node_hash(zeros[level - 1], zeros[level - 1])?);
        }
        Ok(zeros)
    }

    /// Root of the empty depth-`depth` tree (the chain seeds with `empty_leaf = 0`).
    pub fn empty_root(empty_leaf: S::Field, depth: usize) -> Result<S::Field, Error> {
        Ok(Self::zero_ladder(empty_leaf, depth)?[depth])
    }

    /// Stateless frontier append (the `0x0204` precompile kernel): append `leaf`
    /// at `next_index` to the given `frontier` + `zeros` ladder, returning the
    /// single changed slot and the new root.
    pub fn frontier_append(
        frontier: &[S::Field],
        next_index: u64,
        leaf: S::Field,
        zeros: &[S::Field],
    ) -> Result<Append<S::Field>, Error> {
        let depth = frontier.len();
        if zeros.len() != depth + 1 {
            return Err(Error::Merkle(format!(
                "frontier_append: zeros.len() ({}) must be frontier.len()+1 ({})",
                zeros.len(),
                depth + 1
            )));
        }
        if next_index >= (1u64 << depth) {
            return Err(Error::Merkle(format!(
                "frontier_append: next_index {next_index} overflows depth-{depth} tree"
            )));
        }

        let mut current = leaf;
        let mut index = next_index;
        let mut changed: Option<(usize, S::Field)> = None;
        for level in 0..depth {
            if index & 1 == 0 {
                // Left child: the accumulated subtree becomes the new frontier
                // entry the first time we hit a zero bit; pair with the zeros.
                if changed.is_none() {
                    changed = Some((level, current));
                }
                current = Self::node_hash(current, zeros[level])?;
            } else {
                // Right child: merge with the waiting left sibling.
                current = Self::node_hash(frontier[level], current)?;
            }
            index >>= 1;
        }

        let (changed_level, new_subtree) = match changed {
            Some(c) => c,
            // Tree-completing append: no new left subtree waits; report the top
            // slot unchanged.
            None => (depth - 1, frontier[depth - 1]),
        };
        Ok(Append {
            changed_level,
            new_subtree,
            new_root: current,
        })
    }

    /// Recompute a root from an inclusion path: the `leaf`, its `leaf_index`,
    /// and the sibling hash at each level bottom-up. The index bits select
    /// left/right per level, so no per-element side flag is stored.
    pub fn root_from_inclusion_path(
        leaf: S::Field,
        leaf_index: u64,
        siblings: &[S::Field],
    ) -> Result<S::Field, Error> {
        let depth = siblings.len();
        if leaf_index >= (1u64 << depth) {
            return Err(Error::Merkle(format!(
                "root_from_inclusion_path: leaf_index {leaf_index} overflows depth-{depth} tree"
            )));
        }
        let mut current = leaf;
        let mut index = leaf_index;
        for sibling in siblings {
            current = if index & 1 == 0 {
                Self::node_hash(current, *sibling)?
            } else {
                Self::node_hash(*sibling, current)?
            };
            index >>= 1;
        }
        Ok(current)
    }

    /// A new empty tree of `depth` (empty leaf `0`, matching the chain).
    pub fn new(depth: usize) -> Result<Self, Error> {
        let zeros = Self::zero_ladder(S::Field::zero(), depth)?;
        let root = zeros[depth];
        Ok(Self {
            depth,
            frontier: vec![S::Field::zero(); depth],
            next_index: 0,
            zeros,
            root,
        })
    }

    /// Tree depth.
    pub fn depth(&self) -> usize {
        self.depth
    }
    /// Index the next appended leaf will occupy.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }
    /// Current tree root.
    pub fn root(&self) -> S::Field {
        self.root
    }

    /// Append `leaf` at the next index, updating the frontier + root. Returns
    /// the leaf's index and the frontier change.
    pub fn append(&mut self, leaf: S::Field) -> Result<(u64, Append<S::Field>), Error> {
        let index = self.next_index;
        let ins = Self::frontier_append(&self.frontier, index, leaf, &self.zeros)?;
        self.frontier[ins.changed_level] = ins.new_subtree;
        self.root = ins.new_root;
        self.next_index += 1;
        Ok((index, ins))
    }

    /// The inclusion path for `leaf_index` in an otherwise-empty tree of this
    /// depth (every sibling is the empty-subtree root at its level) — the path
    /// for a freshly-inserted leaf before any sibling is filled.
    pub fn empty_inclusion_path(&self, leaf_index: u64) -> InclusionPath<S> {
        InclusionPath {
            leaf_index,
            siblings: self.zeros[..self.depth].to_vec(),
        }
    }
}

/// A Merkle inclusion (membership) proof: the leaf's index plus the sibling
/// hash at each level, bottom-up. `siblings.len()` is the tree depth.
pub struct InclusionPath<S: Suite> {
    /// The leaf's position in the tree.
    pub leaf_index: u64,
    /// Sibling hashes, bottom-up.
    pub siblings: Vec<S::Field>,
}

// Manual `Clone` so the marker `S` need not be `Clone`.
impl<S: Suite> Clone for InclusionPath<S> {
    fn clone(&self) -> Self {
        Self {
            leaf_index: self.leaf_index,
            siblings: self.siblings.clone(),
        }
    }
}

impl<S: Suite> InclusionPath<S> {
    /// The tree depth this path covers.
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// Resolve the tree root this path commits `leaf` to.
    pub fn root(&self, leaf: S::Field) -> Result<S::Field, Error> {
        Imt::<S>::root_from_inclusion_path(leaf, self.leaf_index, &self.siblings)
    }

    /// The in-circuit direction bits: a circuit's `merkle_path_indices` are `1`
    /// when the current node is the **left** child (sibling on the right) and
    /// `0` otherwise — the complement of `leaf_index`'s bit at each level (bit
    /// `0` => current is left).
    pub fn circuit_indices(&self) -> Vec<u8> {
        (0..self.depth())
            .map(|i| {
                if (self.leaf_index >> i) & 1 == 0 {
                    1
                } else {
                    0
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PsoV1;
    use ark_ff::PrimeField;

    type Fr = <PsoV1 as Suite>::Field;

    /// Appending a leaf to an empty tree gives the same root its (empty-tree)
    /// inclusion path resolves to, for any suite.
    #[test]
    fn append_matches_inclusion_path() {
        let mut tree = Imt::<PsoV1>::new(8).unwrap();
        let path = tree.empty_inclusion_path(0);
        let leaf = Fr::from(7u64);
        let (index, append) = tree.append(leaf).unwrap();
        assert_eq!(index, 0);
        assert_eq!(path.root(leaf).unwrap(), append.new_root);
        assert_eq!(path.circuit_indices(), vec![1u8; 8]);
    }

    /// The depth-32 empty-tree root for `PsoV1` must match the chain's pinned
    /// `TributeDraft.EMPTY_TREE_ROOT_DEPTH32`. Value is the **Poseidon2** root
    /// (the chain's commitment tree must adopt the same Poseidon2 constant).
    #[test]
    fn empty_root_matches_chain_constant() {
        let root = Imt::<PsoV1>::empty_root(Fr::zero(), 32).unwrap();
        let hex = "0b59baa35b9dc267744f0ccb4e3b0255c1fc512460d91130c6bc19fb2668568d";
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        assert_eq!(root, Fr::from_be_bytes_mod_order(&bytes));
    }
}
