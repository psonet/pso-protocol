//! Generic entity model — **traits only**.
//!
//! An entity is a declarative preimage: a *seed* (folded to the id) and a
//! *body* (folded from the id to the hash). An entity *encodes itself*: it
//! pushes its members — through [`crate::codec::FieldEncode`] — in
//! canonical order, so the named, typed structure of an NFT lives in the
//! type, not in an out-of-band filling convention.
//!
//! This core declares only the [`Entity`] and [`Owned`] traits. The
//! concrete entity types (Solidity-mirroring `SpendingUnit`,
//! `TributeDraft`, …) live in consumer crates (e.g. `pso-integration`),
//! where `#[derive(Entity)]` generates these impls from `#[pso(...)]`
//! field roles.

use crate::error::Error;
use crate::suite::Suite;

/// A hashable entity, generic over the suite's field.
///
/// An entity says *what* to hash and in *what* order; the suite's `Hash`
/// does the folding, so an entity never says *how*. `id_seed` plus
/// `encode_id_body` fold to the id; the id plus `encode_body` fold to the
/// entity hash.
pub trait Entity<S: Suite> {
    /// Seed of the id accumulator (a single field element). Fallible
    /// because the seed may be a `bytes32` that must decode canonically.
    fn id_seed(&self) -> Result<S::Field, Error>;
    /// Append the fields folded onto the seed to produce the id (push
    /// nothing if the id is stored directly, e.g. a random id).
    fn encode_id_body(&self, out: &mut Vec<S::Field>) -> Result<(), Error>;
    /// Append the entity body, folded from the id to produce the hash.
    fn encode_body(&self, out: &mut Vec<S::Field>) -> Result<(), Error>;

    /// The entity id (rolling-hash seed of the entity hash).
    fn id(&self) -> Result<S::Field, Error> {
        let mut body = Vec::new();
        self.encode_id_body(&mut body)?;
        S::nft_hash(self.id_seed()?, &body)
    }

    /// The canonical entity hash.
    fn entity_hash(&self) -> Result<S::Field, Error> {
        let mut body = Vec::new();
        self.encode_body(&mut body)?;
        S::nft_hash(self.id()?, &body)
    }
}

/// An entity that carries a `derivedOwner`.
pub trait Owned<S: Suite> {
    /// The stored owner commitment. Fallible for the same reason as
    /// [`Entity::id_seed`]: it may decode from a `bytes32`.
    fn owner(&self) -> Result<S::Field, Error>;
}

/// The ownership-relevant projection of an entity: its id, `derivedOwner`,
/// and entity hash. This is what an attester sends the client after
/// minting (the full body stays attester-side), and what the client
/// persists to later prove ownership and to reference the NFT on
/// submission (the `id`); `(owner, nft_hash)` are exactly the
/// per-slot public inputs the aggregation circuit consumes.
///
/// It is an [`Entity`] whose hash is *already known*: `entity_hash` returns
/// the stored value, so ownership-witness derivation and aggregation work
/// on a receipt with no access to the original body.
pub struct OwnershipReceipt<S: Suite> {
    /// Stored entity id
    pub id: S::Field,
    /// Stored `derivedOwner`.
    pub owner: S::Field,
    /// Precomputed entity hash.
    pub nft_hash: S::Field,
}

impl<S: Suite> Entity<S> for OwnershipReceipt<S> {
    fn id_seed(&self) -> Result<S::Field, Error> {
        Ok(self.id)
    }
    fn encode_id_body(&self, _out: &mut Vec<S::Field>) -> Result<(), Error> {
        Ok(())
    }
    fn encode_body(&self, _out: &mut Vec<S::Field>) -> Result<(), Error> {
        Ok(())
    }
    // The hash is known up front; skip the body fold entirely.
    fn entity_hash(&self) -> Result<S::Field, Error> {
        Ok(self.nft_hash)
    }
}
impl<S: Suite> Owned<S> for OwnershipReceipt<S> {
    fn owner(&self) -> Result<S::Field, Error> {
        Ok(self.owner)
    }
}
