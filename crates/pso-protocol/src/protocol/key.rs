//! NFT key derivation — generic over the suite.
//!
//! A [`Signer`] is the one key primitive, encapsulating the NFT secret and
//! exposing only the public [`OwnerSeed`] (the embedded public key + nonce
//! that feed `derivedOwner`) and a signing operation. Three constructors
//! cover the real flows:
//!
//! - [`Signer::local`] — local self-issuance: fresh key + nonce generated
//!   internally (e.g. a Tribute Draft).
//! - [`Signer::issue_for_remote`] — **server** side of the static-ECDH consent
//!   box: holding only the recipient's `consent_pk`, derive the NFT key,
//!   return the public [`OwnerSeed`] + the `opaque_pk` transcript, and
//!   **destroy** the secret (forward secrecy). The server never retains a
//!   signer.
//! - [`Signer::from_exchange`] — **client** side: reconstruct the same NFT
//!   secret from the retained `consent_sk`, the received `opaque_pk`, and
//!   the nonce (DH symmetry), keeping it encapsulated.
//!
//! The box mechanic: server computes `nft_sk = KDF(([opaque_sk]·consent_pk).x,
//! nonce)`; the client recomputes the same shared point as
//! `[consent_sk]·opaque_pk`, so `nft_sk` never crosses the wire.

use ark_std::rand::Rng;
use ark_std::UniformRand;
use zeroize::Zeroize;

use crate::error::Error;
use crate::primitive::curve::{base_to_scalar, Affine};
use crate::primitive::exchange::KeyExchange;
use crate::primitive::kdf::Kdf;
use crate::primitive::signature::{EmbeddedSignature, SignatureScheme};
use crate::suite::Suite;

/// Convenience alias: the signing secret key type of a suite.
pub type SecretKeyOf<S> = <<S as Suite>::Signature as SignatureScheme>::SecretKey;

/// A stored secret scalar that wipes itself on drop and is never *implicitly*
/// copied.
///
/// arkworks field elements (`Fr`) are `Copy` and *do* implement [`Zeroize`],
/// but they never zeroize on drop: a `Copy` type cannot have a `Drop` impl, and
/// `Copy` lets the compiler duplicate the value into temporaries a later
/// `.zeroize()` can't reach. Holding a secret in this non-`Copy` newtype from
/// the moment it is produced keeps it to a single, drop-wiped location instead
/// of leaking copies the optimizer makes. Read it only by reference via
/// [`expose`](Self::expose) for the curve arithmetic that needs it; never move
/// or copy the inner value back out.
///
/// Caveat: this cannot un-`Copy` the scalar itself, so transient copies made by
/// the arithmetic that consumes `expose()` (`[sk]·G`, `e·sk`) still live until
/// their stack frames are reused. The guarantee is for the *stored* key, which
/// is the long-lived target.
pub struct SecretScalar<T: Zeroize>(T);

impl<T: Zeroize> SecretScalar<T> {
    /// Wrap a freshly-produced secret scalar.
    pub fn new(secret: T) -> Self {
        Self(secret)
    }

    /// Borrow the inner scalar for curve arithmetic. Do not copy it out.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> Drop for SecretScalar<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> zeroize::ZeroizeOnDrop for SecretScalar<T> {}

/// The data that determines `derivedOwner`: the NFT public key (on the
/// embedded curve) and its nonce.
pub struct OwnerSeed<S: Suite> {
    /// `nft_pk` on the embedded curve.
    pub pk: Affine<S::Curve>,
    /// Per-NFT nonce.
    pub nonce: S::Field,
}

impl<S: Suite> OwnerSeed<S> {
    /// `derivedOwner = owner_commit(pk, nonce)`.
    pub fn derive_owner(&self) -> Result<S::Field, Error> {
        S::derive_owner(&self.pk, self.nonce)
    }
}

/// A retained NFT secret key, held in a wiping [`SecretScalar`].
pub struct NftSecret<S: Suite> {
    /// The signing secret. Private + zeroizing: construct via [`NftSecret::new`]
    /// and read it only through [`public_key`](Self::public_key) / signing.
    sk: SecretScalar<SecretKeyOf<S>>,
}

impl<S: Suite> NftSecret<S> {
    /// Wrap a raw signing secret so it zeroizes on drop.
    pub fn new(sk: SecretKeyOf<S>) -> Self {
        Self {
            sk: SecretScalar::new(sk),
        }
    }
}

impl<S> NftSecret<S>
where
    S: Suite,
    S::Signature: EmbeddedSignature<S::Curve>,
{
    /// `pk = [sk]·G`.
    pub fn public_key(&self) -> Result<Affine<S::Curve>, Error> {
        S::Signature::public_key(self.sk.expose())
    }
}

/// A source of NFT signing authority that **never exposes the secret key**
/// to the caller. It is bound to an [`OwnerSeed`] (the public key + nonce
/// that `derivedOwner` commits to) and signs the ownership payload,
/// keeping the secret inside. Implemented by the encapsulating [`Signer`];
/// a custom impl can back signing with an HSM or a remote signer.
///
/// Because the signer carries the nonce, `ownership_witness` takes only the
/// signer — there is no separate nonce argument to keep in sync.
pub trait NftSigner<S: Suite> {
    /// The owner seed (public key + nonce) this signer is bound to.
    fn owner_seed(&self) -> &OwnerSeed<S>;
    /// Sign the ownership `payload`.
    fn sign<R: Rng>(
        &self,
        rng: &mut R,
        payload: S::Field,
    ) -> Result<<S::Signature as SignatureScheme>::Signature, Error>;
    /// The NFT public key (its coords are bound via `derivedOwner`).
    fn public_key(&self) -> Affine<S::Curve> {
        self.owner_seed().pk
    }
}

/// An NFT signer that keeps its secret key **encapsulated** — the caller
/// gets one of these instead of a raw key. Construct it with
/// [`Signer::local`] (self-issuance), [`Signer::from_exchange`] (client
/// side of the consent box), or [`Signer::from_secret`] (bind an existing
/// key). The server side of the consent box uses [`Signer::issue_for_remote`],
/// which returns the public artifacts *without* a retained signer.
///
/// The public [`OwnerSeed`] is reached via [`NftSigner::owner_seed`]. Prove
/// ownership by passing `&Signer` where an [`NftSigner`] is expected. If the
/// caller genuinely needs the raw key (e.g. to persist it),
/// [`Signer::secret`] / [`Signer::into_secret`] hand it over explicitly.
pub struct Signer<S: Suite> {
    secret: NftSecret<S>,
    seed: OwnerSeed<S>,
}

impl<S> Signer<S>
where
    S: Suite,
    S::Signature: EmbeddedSignature<S::Curve>,
{
    /// Local self-issuance: generate a fresh NFT key + nonce internally.
    pub fn local(rng: &mut impl Rng) -> Result<Self, Error> {
        let (sk, pk) = S::Signature::keypair(rng);
        let nonce = S::Field::rand(rng);
        Ok(Self {
            secret: NftSecret::new(sk),
            seed: OwnerSeed { pk, nonce },
        })
    }

    /// Server side of the consent box: holding only the recipient's
    /// `consent_pk`, derive the NFT key via static ECDH, and return the
    /// public [`OwnerSeed`] (→ `derivedOwner` to publish) plus the
    /// `opaque_pk` transcript to ship. The NFT secret and the ephemeral
    /// `opaque_sk` are dropped here — forward secrecy — so no signer is
    /// returned (the *remote* reconstructs one via [`Signer::from_exchange`]).
    pub fn issue_for_remote<X: KeyExchange<S::Field>>(
        rng: &mut impl Rng,
        consent_pk: &X::Public,
    ) -> Result<(OwnerSeed<S>, X::Public), Error> {
        let (opaque_sk, opaque_pk) = X::random_keypair(rng);
        let nonce = S::Field::rand(rng);
        let opaque_sk = SecretScalar::new(opaque_sk);
        let shared = X::shared(opaque_sk.expose(), consent_pk)?;
        let nft_sk = SecretScalar::new(derive_nft_secret::<S>(shared, nonce)?);
        let pk = S::Signature::public_key(nft_sk.expose())?;
        // opaque_sk and nft_sk zeroize on drop here (forward secrecy).
        Ok((OwnerSeed { pk, nonce }, opaque_pk))
    }

    /// Client side of the consent box: reconstruct the NFT secret from the
    /// retained `consent_sk`, the received `opaque_pk`, and the nonce.
    pub fn from_exchange<X: KeyExchange<S::Field>>(
        consent_sk: &X::Secret,
        opaque_pk: &X::Public,
        nonce: S::Field,
    ) -> Result<Self, Error> {
        let shared = X::shared(consent_sk, opaque_pk)?;
        let secret = NftSecret::new(derive_nft_secret::<S>(shared, nonce)?);
        let pk = secret.public_key()?;
        Ok(Self {
            secret,
            seed: OwnerSeed { pk, nonce },
        })
    }

    /// Bind an existing NFT secret to the `nonce` its `derivedOwner`
    /// commits to (recomputes the public key).
    pub fn from_secret(secret: NftSecret<S>, nonce: S::Field) -> Result<Self, Error> {
        let pk = secret.public_key()?;
        Ok(Self {
            secret,
            seed: OwnerSeed { pk, nonce },
        })
    }

    /// Borrow the encapsulated NFT secret (e.g. to persist it to a keystore).
    pub fn secret(&self) -> &NftSecret<S> {
        &self.secret
    }

    /// Consume the signer and hand back the NFT secret.
    pub fn into_secret(self) -> NftSecret<S> {
        self.secret
    }
}

impl<S> NftSigner<S> for Signer<S>
where
    S: Suite,
    S::Signature: EmbeddedSignature<S::Curve>,
{
    fn owner_seed(&self) -> &OwnerSeed<S> {
        &self.seed
    }
    fn sign<R: Rng>(
        &self,
        rng: &mut R,
        payload: S::Field,
    ) -> Result<<S::Signature as SignatureScheme>::Signature, Error> {
        S::Signature::sign(rng, self.secret.sk.expose(), payload)
    }
}

/// Map a KDF output (base field) into the embedded scalar field and adopt
/// it as a signing secret: the shared `nft_sk` construction.
fn derive_nft_secret<S>(shared: S::Field, nonce: S::Field) -> Result<SecretKeyOf<S>, Error>
where
    S: Suite,
    S::Signature: EmbeddedSignature<S::Curve>,
{
    let kdf_out = S::Kdf::derive(&[shared, nonce])?;
    let scalar = base_to_scalar::<S::Curve>(&kdf_out);
    Ok(S::Signature::secret_from_scalar(scalar))
}
