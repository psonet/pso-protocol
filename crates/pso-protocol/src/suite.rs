//! The suite: one type that selects every swappable primitive and
//! provides the protocol's formulas as **overridable defaults**.
//!
//! Two kinds of pluggability live here:
//!
//! 1. **Primitive swap** — change an associated type (`Curve`, `Hash`,
//!    `Signature`, `Kdf`). Every formula built on it follows automatically.
//! 2. **Formula swap** — override a default method (`owner_commit`,
//!    `binding`, `signing_payload`) to change arity/layout without
//!    touching the primitives.
//!
//! All protocol logic (`crate::protocol`) is written against `S: Suite`,
//! so concrete PSO behaviour is just the default impls under the
//! [`crate::PsoV1`] selection — not hard-coded anywhere.

use ark_ff::PrimeField;
use ark_std::rand::Rng;

use crate::error::Error;
use crate::primitive::curve::{coords, Affine, EmbeddedCurve};
use crate::primitive::exchange::KeyExchange;
use crate::primitive::hash::FieldHasher;
use crate::primitive::kdf::Kdf;
use crate::primitive::signature::{EmbeddedSignature, SignatureScheme};
use crate::protocol::key::{OwnerSeed, Signer};

/// Public-key type of a suite's [`Suite::Exchange`].
pub type ExchangePublic<S> = <<S as Suite>::Exchange as KeyExchange<<S as Suite>::Field>>::Public;
/// Secret-key type of a suite's [`Suite::Exchange`].
pub type ExchangeSecret<S> = <<S as Suite>::Exchange as KeyExchange<<S as Suite>::Field>>::Secret;

/// A complete protocol parameterization.
pub trait Suite: 'static {
    /// Native proving field.
    type Field: PrimeField;
    /// Embedded curve (its base field is `Field`).
    type Curve: EmbeddedCurve<Base = Self::Field>;
    /// Field hash (owner, entity, payload, binding, Merkle).
    type Hash: FieldHasher<Self::Field>;
    /// Signature scheme; its public key is the curve's affine point.
    type Signature: SignatureScheme<Field = Self::Field, PublicKey = Affine<Self::Curve>>;
    /// Key-derivation function.
    type Kdf: Kdf<Self::Field>;
    /// Key exchange backing the consent box (PSO: ECDH on the embedded curve).
    type Exchange: KeyExchange<Self::Field>;

    /// Protocol version / domain separator, folded into [`Suite::binding`].
    /// Distinct values make two suite versions' submission bindings (and
    /// thus their signatures + aggregation public inputs) cryptographically
    /// distinct, even for identical inputs — so a proof for one version
    /// can't be replayed against another. Identity hashes (`derive_owner`,
    /// `nft_hash`) are deliberately *not* domain-separated, so an NFT keeps
    /// its identity across versions. Defaults to 0 (unversioned).
    const DOMAIN: u64 = 0;

    // ---- Signer initiation (uses `Self::Exchange`; no exchange type to pass) ----

    /// Generate a random keypair for this suite's key exchange.
    fn random_keypair(rng: &mut impl Rng) -> (ExchangeSecret<Self>, ExchangePublic<Self>)
    where
        Self: Sized,
    {
        Self::Exchange::random_keypair(rng)
    }

    /// Local self-issuance: a [`Signer`] whose key is generated internally.
    fn local_signer(rng: &mut impl Rng) -> Result<Signer<Self>, Error>
    where
        Self: Sized,
        Self::Signature: EmbeddedSignature<Self::Curve>,
    {
        Signer::local(rng)
    }

    /// Server side of the consent box: derive the owner seed + `opaque_pk`
    /// transcript for `consent_pk`; the secret is destroyed (forward secrecy).
    fn issue_for_remote(
        rng: &mut impl Rng,
        consent_pk: &ExchangePublic<Self>,
    ) -> Result<(OwnerSeed<Self>, ExchangePublic<Self>), Error>
    where
        Self: Sized,
        Self::Signature: EmbeddedSignature<Self::Curve>,
    {
        Signer::issue_for_remote::<Self::Exchange>(rng, consent_pk)
    }

    /// Client side of the consent box: reconstruct the [`Signer`].
    fn signer_from_remote(
        consent_sk: &ExchangeSecret<Self>,
        opaque_pk: &ExchangePublic<Self>,
        nonce: Self::Field,
    ) -> Result<Signer<Self>, Error>
    where
        Self: Sized,
        Self::Signature: EmbeddedSignature<Self::Curve>,
    {
        Signer::from_exchange::<Self::Exchange>(consent_sk, opaque_pk, nonce)
    }

    // ---- Formulas (override to change a formula; defaults are the PSO ones) ----

    /// `derivedOwner = Hash([pk.x, pk.y, nonce])` (Poseidon3 in PSO).
    fn derive_owner(pk: &Affine<Self::Curve>, nonce: Self::Field) -> Result<Self::Field, Error> {
        let (x, y) = coords::<Self::Curve>(pk)?;
        Self::Hash::hash(&[x, y, nonce])
    }

    /// Entity hash: iterated hash seeded at `id` over `body`.
    fn nft_hash(id: Self::Field, body: &[Self::Field]) -> Result<Self::Field, Error> {
        Self::Hash::iterate(id, body)
    }

    /// The Schnorr message: `Hash([nft_hash, nonce, binding])`
    /// (Poseidon3 in PSO).
    fn signing_payload(
        nft_hash: Self::Field,
        nonce: Self::Field,
        binding: Self::Field,
    ) -> Result<Self::Field, Error> {
        Self::Hash::hash(&[nft_hash, nonce, binding])
    }

    /// Submission binding `Hash([DOMAIN, sender, cid_lo, cid_hi, chain_id])`
    /// (Poseidon5 + uint256 limb split in PSO). The leading [`Suite::DOMAIN`]
    /// folds the protocol version into the binding, which flows into every
    /// signature ([`Suite::signing_payload`]) and the aggregation public
    /// inputs — so the version is bound into the whole proof/submission path.
    fn binding(
        sender: &[u8; 20],
        commitment_id: &[u8; 32],
        chain_id: u64,
    ) -> Result<Self::Field, Error> {
        let domain = Self::Field::from(Self::DOMAIN);
        let sender_fr = crate::codec::field_from_be_bytes::<Self::Field>(sender);
        // uint256 split into two 128-bit limbs [lo, hi] — the same split
        // consumers apply to any `uint256` entity field.
        let [cid_lo, cid_hi] = crate::codec::u256_limbs_be::<Self::Field>(commitment_id);
        let chain_fr = Self::Field::from(chain_id);
        Self::Hash::hash(&[domain, sender_fr, cid_lo, cid_hi, chain_fr])
    }
}
