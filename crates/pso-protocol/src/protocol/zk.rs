//! ZK proof backend seams, bound to a [`Circuit`].
//!
//! A [`Circuit`] is the type-level structure of a statement: it binds the
//! private *witness* to its *public inputs* (the claim) — the field
//! elements committed into the proof. The concrete
//! proving artifacts — the compiled circuit and the verifying key, plus
//! its hash — live with the backend in the zk crates (e.g.
//! `pso-zk-circuits-canonical`); a circuit type here is the contract those
//! backends and the protocol agree on.
//!
//! [`ProofGenerator`]/[`ProofVerifier`] are the backend seams,
//! parameterized by the circuit so a prover and a verifier for the *same*
//! `C` necessarily agree on the witness and public-input types.

use crate::error::Error;
use crate::primitive::curve::Grumpkin;
use crate::primitive::signature::{EmbeddedSignature, SignatureScheme};
use crate::suite::Suite;

/// A circuit / statement: the binding between a *witness* (the private
/// inputs the circuit constrains) and the *public inputs* (the claim the
/// proof attests). The two are separate types — the public inputs are not
/// derived from the witness here; the prover supplies both.
pub trait Circuit<S: Suite> {
    /// The private witness the circuit constrains.
    type Witness;
    /// The public inputs (the claim) the circuit exposes.
    type PublicInputs;

    /// Flatten the public inputs into field elements, in circuit order —
    /// the values (owner / hashes / binding …) bound into the proof. The
    /// *verify-side* mapping (what the on-chain verifier checks the proof
    /// against).
    fn public_inputs(public: &Self::PublicInputs) -> Vec<S::Field>;

    /// Flatten the full witness — every ABI parameter (private and public, in
    /// `main()` declaration order; structs, arrays and byte elements expanded) —
    /// into field elements in ACIR witness-index order: index `i` in the
    /// returned vec is exactly ACIR `Witness(i)`. The *prove-side* mapping a noir
    /// backend lowers into a `WitnessMap`.
    ///
    /// Sits next to [`public_inputs`](Circuit::public_inputs) so the
    /// prover and verifier consume one build-derived source of truth and cannot
    /// drift from the ABI.
    fn witness_inputs(witness: &Self::Witness, public: &Self::PublicInputs) -> Vec<S::Field>;
}

/// A [`Suite`] usable with the canonical noir circuits. The circuits are
/// compiled for the BN254/Grumpkin cycle and verify a 64-byte `s ‖ e` Grumpkin
/// Schnorr in-circuit, so a compatible suite must select exactly those: field
/// `ark_bn254::Fr`, curve [`Grumpkin`], and a signature scheme producing
/// `[u8; 64]`. The circuit layer is generic over this bound instead of
/// hardcoding `PsoV1` — so `PsoV1` and any future same-cycle `PsoV2` both work.
///
/// Lives here (the circuit seam) rather than in the concrete circuit crate so a
/// noir backend can be generic over circuits without depending on
/// `pso-zk-circuits-canonical`.
pub trait CircuitSuite:
    Suite<
    Field = ark_bn254::Fr,
    Curve = Grumpkin,
    Signature: EmbeddedSignature<Grumpkin> + SignatureScheme<Signature = [u8; 64]>,
>
{
}

impl<S> CircuitSuite for S where
    S: Suite<
        Field = ark_bn254::Fr,
        Curve = Grumpkin,
        Signature: EmbeddedSignature<Grumpkin> + SignatureScheme<Signature = [u8; 64]>,
    >
{
}

/// The canonical on-chain identity of a circuit — content-derived and
/// **suite-independent** (a circuit's bytecode/VK don't depend on which
/// [`CircuitSuite`] proves it). Mirrors `pso-zk-circuits-canonical`'s
/// `CircuitDescriptor`. Implemented (build-generated) by every circuit marker.
pub trait CircuitId {
    /// Canonical dotted label, e.g. `pso.ownership` / `pso.flat_aggregation.n2`.
    const LABEL: &'static str;
    /// Semver-style version string ("1.0.0"). Not authoritative.
    const VERSION: &'static str;
    /// `keccak256(base64_decode(bytecode))` — the authoritative on-chain
    /// identity the `zk_verify` precompile matches against.
    const CIRCUIT_HASH: [u8; 32];
    /// Base64-encoded ACIR bytecode (the preimage of [`CircuitId::CIRCUIT_HASH`]).
    const BYTECODE_B64: &'static str;
    /// Canonical UltraHonkKeccak verification key bytes, derived from the bytecode.
    const VK_BYTES: &'static [u8];
    /// Pre-computed `keccak256(VK_BYTES)`.
    const VK_HASH: [u8; 32];
}

/// A proof-generation backend for a specific [`Circuit`] — implemented by
/// the proof crate (e.g. `pso-zk-circuits` for noir).
pub trait ProofGenerator<S: Suite, C: Circuit<S>> {
    /// The proof representation this backend produces (bytes, a noir
    /// proof, …).
    type Proof;
    /// Generate a proof: `witness` is the private inputs, `public` the
    /// claim (public inputs) the proof must attest.
    fn generate(
        &self,
        witness: &C::Witness,
        public: &C::PublicInputs,
    ) -> Result<Self::Proof, Error>;
}

/// A proof-verification backend for a specific [`Circuit`] — implemented
/// next to the verifier.
pub trait ProofVerifier<S: Suite, C: Circuit<S>> {
    /// The proof representation this backend verifies.
    type Proof;
    /// Verify `proof` against `public`.
    fn verify(&self, public: &C::PublicInputs, proof: &Self::Proof) -> Result<bool, Error>;
}
