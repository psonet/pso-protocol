//! ZK-circuit witness data types and the traits NFT types implement
//! to be eligible for proof generation.
//!
//! This module owns the **data layout** of every witness — the exact
//! byte arrangement the Noir circuits read. Any change here is a
//! consensus-breaking change requiring a circuit recompile and a new
//! canonical descriptor.
//!
//! ## What does not live here
//!
//! The `generate_witness` implementations are deliberately not in this
//! crate. They depend on `k256` for ECDSA signing and SEC1 coordinate
//! extraction, which would force `pso-protocol` (and therefore every
//! on-chain precompile) to drag in elliptic-curve cryptography it
//! doesn't need. The blanket `GenerateWitness<Ctx>` impls live in
//! `pso-integration`, on the wallet side of the boundary.
//!
//! ## Debug redaction (DH-6)
//!
//! Every type that holds sensitive cryptographic material (private keys,
//! nonces, signatures) has a manual `Debug` impl that emits
//! `[REDACTED]` instead of the raw bytes. Adding a field to one of these
//! types **must** preserve that redaction; see the regression tests at
//! the bottom of this file.

use ark_bn254::Fr;
use core::fmt;

use crate::error::ProtocolError;
use crate::merkle::MerklePathElement;

// =====================================================================
// Traits
// =====================================================================

/// An NFT that has a provable owner.
///
/// The ownership value is a pre-computed Poseidon5 hash of the owner's
/// public-key coordinates plus a nonce (see
/// `pso_protocol::ownership::compute_ownership`). It is stored on the
/// NFT and produced by this getter.
///
/// **Note:** the `sign_ownership` default implementation that lived on
/// the original `pso-zk-core::OwnableNFT` trait does **not** live here.
/// ECDSA signing is k256-bound and stays in the integration crate.
/// Implementations of this trait remain trivial getters.
pub trait OwnableNFT {
    /// Returns the stored ownership hash.
    fn ownership(&self) -> Fr;
}

/// An NFT whose data can be hashed into a single field element
/// (Merkle leaf).
///
/// Each NFT type implements its own hash formula. The hash is
/// self-contained: the NFT stores all the necessary data internally,
/// including the ownership value when needed.
pub trait HashableNFT {
    /// Compute the entity hash for this NFT.
    fn hash(&self) -> Result<Fr, ProtocolError>;
}

/// Trait for generating ZK witnesses from NFT types.
///
/// Generic over the context `Ctx` which determines both the required
/// inputs and the produced witness type. **Implementations live in
/// `pso-integration`** because building a witness requires extracting
/// SEC1 coordinates from a `k256::SecretKey` and ECDSA-signing the
/// ownership / binding hashes — operations this crate cannot perform
/// without dragging in elliptic-curve dependencies.
pub trait GenerateWitness<Ctx> {
    /// The witness type produced by this implementation.
    type Witness;

    /// Build the witness from `self` and `ctx`.
    fn generate_witness(&self, ctx: Ctx) -> Result<Self::Witness, ProtocolError>;
}

// =====================================================================
// Ownership-only witness
// =====================================================================

/// Private inputs for ownership-only proof.
///
/// Sensitive fields (nonce, public key coordinates) are redacted in
/// debug output to prevent accidental exposure of cryptographic
/// material. See DH-6 for policy.
#[derive(Clone)]
pub struct OwnershipPrivateInputs {
    /// Nonce for ZKP, 32-byte BE Fr.
    pub nonce: [u8; 32],
    /// Grumpkin public-key X coordinate, 32-byte BE Fr.
    pub public_key_x: [u8; 32],
    /// Grumpkin public-key Y coordinate, 32-byte BE Fr.
    pub public_key_y: [u8; 32],
}

impl fmt::Debug for OwnershipPrivateInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnershipPrivateInputs")
            .field("nonce", &"[REDACTED]")
            .field("public_key_x", &"[REDACTED]")
            .field("public_key_y", &"[REDACTED]")
            .finish()
    }
}

/// Public inputs for the §4.2 single-NFT ownership proof.
///
/// `nft_hash` was added in the §4.2 redesign — the Schnorr-signed
/// payload is `Poseidon2(nft_hash, nonce).to_be_bytes()` per the
/// Noir circuit (`pso-circuit-core/src/ownership.nr`), so the
/// circuit takes the entity hash as a public input and the
/// verifier recomputes the same pre-hash to bind the proof to a
/// specific NFT.
///
/// `signature` is **logically private** in the §4.2 circuit (the
/// circuit's `main()` declares it as a private parameter). It lives
/// in this struct for historical / serialization reasons — the
/// witness map builder routes it to the private witness slot.
///
/// All `[u8; 32]` Fr fields are **big-endian** as of pso-protocol
/// v0.3.0 (the LE convention before that was Rust-side only and
/// inconsistent with the Solidity / barretenberg-rs / on-chain
/// BE convention).
#[derive(Clone, Debug)]
pub struct OwnershipPublicInputs {
    /// Poseidon5 owner commitment (ownership proof output), 32-byte BE Fr.
    pub ownership: [u8; 32],
    /// Per-NFT entity hash. 32-byte BE Fr. Public.
    pub nft_hash: [u8; 32],
    /// Grumpkin Schnorr signature over
    /// `Poseidon2(nft_hash, nonce).to_be_bytes()`, 64 bytes (`s || e`,
    /// each 32 bytes BE). **Private witness** — exposed in this
    /// struct for convenience but routed to the private slot by the
    /// witness builders.
    pub signature: [u8; 64],
}

/// Complete witness for the ownership-only circuit.
#[derive(Clone, Debug)]
pub struct OwnershipWitness {
    /// Private inputs (nonce, public-key coordinates).
    pub private_inputs: OwnershipPrivateInputs,
    /// Public inputs (ownership hash, ECDSA signature).
    pub public_inputs: OwnershipPublicInputs,
}

// =====================================================================
// Full proof witness (ownership + Merkle inclusion)
// =====================================================================

/// Private inputs for the full proof circuit (ownership + inclusion).
///
/// `ownership` is redacted in debug; `merkle_path` is public data so
/// shown normally.
#[derive(Clone)]
pub struct FullProofPrivateInputs {
    /// Ownership private inputs (nonce, pk_x, pk_y).
    pub ownership: OwnershipPrivateInputs,
    /// Merkle path of siblings.
    pub merkle_path: Vec<MerklePathElement>,
}

impl fmt::Debug for FullProofPrivateInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FullProofPrivateInputs")
            .field("ownership", &self.ownership)
            .field("merkle_path", &self.merkle_path)
            .finish()
    }
}

/// Public inputs for the full proof circuit (ownership + inclusion).
///
/// The `nft_hash` field deliberately lives inside the embedded
/// `OwnershipPublicInputs` rather than at the top level — there is
/// only one entity hash per proof, and the §4.2 ownership constraint
/// already binds the signature to it. Earlier revisions duplicated
/// it at both levels; that was a red flag and got removed.
#[derive(Clone, Debug)]
pub struct FullProofPublicInputs {
    /// Ownership public inputs (owner commitment, NFT hash, signature).
    /// `ownership.nft_hash` is the single source of truth for the
    /// entity hash; the inclusion check below resolves the Merkle
    /// path against this same value.
    pub ownership: OwnershipPublicInputs,
    /// Merkle root (inclusion proof output), 32-byte BE Fr.
    pub merkle_root: [u8; 32],
}

/// Complete witness for the full proof circuit (ownership + inclusion).
#[derive(Clone, Debug)]
pub struct FullProofWitness {
    /// Private inputs (ownership data, Merkle path).
    pub private_inputs: FullProofPrivateInputs,
    /// Public inputs (ownership hash, signature, entity hash, Merkle root).
    pub public_inputs: FullProofPublicInputs,
}

// =====================================================================
// SU-ownership aggregation witness
// =====================================================================

/// One real (nonce, derived_owner) pair the wallet wants to aggregate.
///
/// `derived_owner` must equal
/// `pso_protocol::ownership::compute_ownership(pk_x, pk_y, nonce)`
/// under the wallet's keypair — the on-chain SU was minted with this
/// value at `SpendingUnit.derivedOwner`. The aggregation circuit
/// re-derives it from `nonce` and asserts equality.
#[derive(Clone, Copy, Debug)]
pub struct AggregationSlot {
    /// Per-SU randomness.
    pub nonce: Fr,
    /// Pre-computed ownership commitment.
    pub derived_owner: Fr,
}

/// Private inputs for the SU-ownership aggregation circuit.
///
/// `nonces` length must equal the circuit's compile-time `N`. For
/// padded slots (when real SU count < tier_n), set the corresponding
/// nonce to any value — the circuit's check trivializes when
/// `derived_owners[i] == 0`.
#[derive(Clone)]
pub struct AggregationPrivateInputs {
    /// Grumpkin public-key X coordinate, 32-byte BE Fr.
    pub public_key_x: [u8; 32],
    /// Grumpkin public-key Y coordinate, 32-byte BE Fr.
    pub public_key_y: [u8; 32],
    /// One Fr nonce per tier slot, 32-byte BE Fr each.
    pub nonces: Vec<[u8; 32]>,
    /// Grumpkin Schnorr signature over `binding_hash.to_be_bytes()`.
    pub signature: [u8; 64],
}

impl fmt::Debug for AggregationPrivateInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AggregationPrivateInputs")
            .field("public_key_x", &"[REDACTED]")
            .field("public_key_y", &"[REDACTED]")
            .field(
                "nonces",
                &format_args!("[REDACTED; {} slots]", self.nonces.len()),
            )
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

/// Public inputs for the SU-ownership aggregation circuit.
///
/// **Order matters** — the wallet feeds these to the circuit in the
/// same order the on-chain `TributeDraft` contract assembles its
/// expected public-input vector: `[derived_owners[0..N], binding_hash]`.
/// The contract byte-compares the proof prefix against this vector.
#[derive(Clone, Debug)]
pub struct AggregationPublicInputs {
    /// One Fr derived-owner per tier slot, 32-byte BE Fr each.
    /// Real slots equal `compute_ownership(pk_x, pk_y, nonces[i])`;
    /// padded slots are 32 zero bytes.
    pub derived_owners: Vec<[u8; 32]>,
    /// `compute_binding_hash(sender, tribute_draft_id, chain_id)`, 32-byte BE Fr.
    pub binding_hash: [u8; 32],
}

/// Complete witness for the SU-ownership aggregation circuit.
#[derive(Clone, Debug)]
pub struct AggregationWitness {
    /// Private inputs.
    pub private_inputs: AggregationPrivateInputs,
    /// Public inputs.
    pub public_inputs: AggregationPublicInputs,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerklePathElementIndex;

    #[test]
    fn ownership_witness_clone() {
        let witness = OwnershipWitness {
            private_inputs: OwnershipPrivateInputs {
                nonce: [0u8; 32],
                public_key_x: [0u8; 32],
                public_key_y: [0u8; 32],
            },
            public_inputs: OwnershipPublicInputs {
                ownership: [0u8; 32],
                nft_hash: [0u8; 32],
                signature: [0u8; 64],
            },
        };
        let cloned = witness.clone();
        assert_eq!(cloned.private_inputs.nonce, witness.private_inputs.nonce);
    }

    #[test]
    fn full_proof_witness_clone() {
        let witness = FullProofWitness {
            private_inputs: FullProofPrivateInputs {
                ownership: OwnershipPrivateInputs {
                    nonce: [0u8; 32],
                    public_key_x: [0u8; 32],
                    public_key_y: [0u8; 32],
                },
                merkle_path: vec![MerklePathElement {
                    node_hash: [0u8; 32],
                    index: MerklePathElementIndex::Skip,
                }],
            },
            public_inputs: FullProofPublicInputs {
                ownership: OwnershipPublicInputs {
                    ownership: [0u8; 32],
                    nft_hash: [0u8; 32],
                    signature: [0u8; 64],
                },
                merkle_root: [0u8; 32],
            },
        };
        let cloned = witness.clone();
        assert_eq!(
            cloned.public_inputs.ownership.nft_hash,
            witness.public_inputs.ownership.nft_hash
        );
        assert_eq!(cloned.private_inputs.merkle_path.len(), 1);
    }

    // --- Debug redaction (DH-6 regression) ---

    #[test]
    fn ownership_private_inputs_debug_redacts_all_fields() {
        let inputs = OwnershipPrivateInputs {
            nonce: [42u8; 32],
            public_key_x: [99u8; 32],
            public_key_y: [88u8; 32],
        };
        let s = format!("{:?}", inputs);
        for needle in ["nonce", "public_key_x", "public_key_y", "[REDACTED]"] {
            assert!(s.contains(needle), "missing {needle} in: {s}");
        }
        // No hex digits of the raw bytes should leak.
        for byte_hex in ["2a", "63", "58"] {
            assert!(!s.contains(byte_hex), "byte {byte_hex} leaked in: {s}");
        }
    }

    #[test]
    fn aggregation_private_inputs_debug_redacts_all_fields() {
        let inputs = AggregationPrivateInputs {
            public_key_x: [0xaau8; 32],
            public_key_y: [0xbbu8; 32],
            nonces: vec![[0xccu8; 32]; 3],
            signature: [0xddu8; 64],
        };
        let s = format!("{:?}", inputs);
        assert!(s.contains("[REDACTED]"));
        assert!(s.contains("3 slots"));
        for byte_hex in ["aa", "bb", "cc", "dd"] {
            assert!(!s.contains(byte_hex), "byte {byte_hex} leaked in: {s}");
        }
    }

    #[test]
    fn full_proof_private_inputs_debug_redacts_ownership_only() {
        let inputs = FullProofPrivateInputs {
            ownership: OwnershipPrivateInputs {
                nonce: [1u8; 32],
                public_key_x: [2u8; 32],
                public_key_y: [3u8; 32],
            },
            merkle_path: vec![],
        };
        let s = format!("{:?}", inputs);
        assert!(s.contains("[REDACTED]"));
        assert!(s.contains("merkle_path"));
    }
}
