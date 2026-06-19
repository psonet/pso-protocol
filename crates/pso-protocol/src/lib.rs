//! # pso-protocol (generic core)
//!
//! Consensus-binding protocol logic written once, against a swappable
//! [`Suite`]. A suite selects the curve, field hash, signature
//! scheme, and KDF, and supplies the entity/owner/binding/payload
//! formulas as overridable defaults.
//!
//! - [`primitive`] — the swappable cryptographic traits + instances.
//! - [`suite`] — the `Suite` trait + default formulas. The production
//!   [`PsoV1`] selection lives at the crate root; a test-only `Mock` suite
//!   lives in the core crate's tests.
//! - [`protocol`] — entity hashing, ownership proofs, and aggregation,
//!   all generic over `S: Suite`.
//!
//! `pso-zk-circuits` and `pso-integration` depend on this crate for the
//! formulas, witness order, and statement types; they provide only the
//! backend `WitnessSink`/`SignatureScheme` impls.

#![forbid(unsafe_code)]

pub mod codec;
pub mod error;
pub mod primitive;
pub mod protocol;
pub mod suite;

pub use codec::{Codec, FieldElement, FieldEncode};
pub use error::Error;
pub use suite::Suite;

/// Production suite, version 1: BN254 / Grumpkin / Poseidon / Schnorr.
///
/// The version is explicit in the type so future parameterization can coexist
/// as `PsoV2`, etc. The **core protocol logic** (`crate::protocol`, the `Suite`
/// formulas, the signature/curve/hash *traits*) is generic over `S: Suite`;
/// this type is one concrete selection of the swappable instances. (The
/// `pso-zk-canonical` circuit layer is deliberately concrete to a BN254 suite —
/// the noir circuits fix the proving field.) `DOMAIN = 1` folds the version
/// into the submission binding, keeping V1 proofs cryptographically distinct
/// from any later version's.
///
/// Every formula is inherited from the [`Suite`] defaults, so this is just the
/// primitive selection. Swapping, say, `Hash` here would re-key the entire
/// protocol with no other edits.
pub struct PsoV1;

impl Suite for PsoV1 {
    type Field = ark_bn254::Fr;
    type Curve = primitive::curve::Grumpkin;
    type Hash = primitive::hash::Poseidon2;
    type Signature = primitive::signature::Schnorr<primitive::curve::Grumpkin>;
    type Kdf = primitive::kdf::PoseidonKdf;
    type Exchange = primitive::exchange::EcdhEmbedded<primitive::curve::Grumpkin>;
    const DOMAIN: u64 = 1;
}
