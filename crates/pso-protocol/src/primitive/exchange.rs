//! Pluggable key exchange (for the consent-box derivation).
//!
//! The box's DH curve is an independent parameter from the embedded
//! signing curve. In production the consent key is secp256k1 and the
//! exchange is secp256k1 ECDH→HKDF; here [`EcdhEmbedded`] runs ECDH on
//! the embedded curve itself so the core is self-contained and testable.
//! Either way the shared secret is surfaced as one native field element
//! (the shared point's x-coordinate, or an HKDF reduction of it) for the
//! suite KDF to consume.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use zeroize::Zeroize;

use crate::error::Error;
use crate::primitive::curve::{coords, Affine, EmbeddedCurve};

/// A Diffie–Hellman exchange whose shared secret is reported as an `F`.
pub trait KeyExchange<F: PrimeField>: 'static {
    /// Exchange public key.
    type Public: Clone;
    /// Exchange secret key. `Zeroize` so an ephemeral box secret can be wiped
    /// (forward secrecy) — see [`SecretScalar`](crate::protocol::key::SecretScalar).
    type Secret: Clone + Zeroize;

    /// Sample an exchange keypair.
    fn random_keypair<R: Rng>(rng: &mut R) -> (Self::Secret, Self::Public);

    /// Shared secret `kdf-input(sk · other)` as a field element.
    /// Must be symmetric: `shared(a, B) == shared(b, A)` when
    /// `A = [a]G`, `B = [b]G`.
    fn shared(sk: &Self::Secret, other: &Self::Public) -> Result<F, Error>;
}

/// ECDH on an embedded curve `C`; shared secret = shared point's x-coord.
pub struct EcdhEmbedded<C>(PhantomData<C>);

impl<C: EmbeddedCurve> KeyExchange<C::Base> for EcdhEmbedded<C> {
    type Public = Affine<C>;
    type Secret = C::Scalar;

    fn random_keypair<R: Rng>(rng: &mut R) -> (Self::Secret, Self::Public) {
        let sk = C::Scalar::rand(rng);
        let pk = C::mul_generator(&sk).into_affine();
        (sk, pk)
    }

    fn shared(sk: &Self::Secret, other: &Self::Public) -> Result<C::Base, Error> {
        let point = other.mul_bigint(sk.into_bigint()).into_affine();
        let (x, _y) = coords::<C>(&point)?;
        Ok(x)
    }
}
