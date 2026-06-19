//! Pluggable embedded curve.
//!
//! An *embedded* curve is one whose base field equals the proving field,
//! so its affine coordinates are native field elements (no limb
//! decomposition, native in-circuit EC ops). Grumpkin is BN254's
//! embedded curve; this trait is the seam that lets the rest of the
//! protocol be written without naming Grumpkin.
//!
//! Curve-form agnostic: the trait is stated over `ark_ec::CurveGroup`, so
//! a short-Weierstrass curve (Grumpkin) or a twisted-Edwards curve
//! (e.g. an ed-on-bn254) both satisfy it.

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};
use zeroize::Zeroize;

use crate::error::Error;

/// A curve whose base field is the native proving field.
pub trait EmbeddedCurve: 'static {
    /// Projective group type.
    type Group: CurveGroup<BaseField = Self::Base, ScalarField = Self::Scalar>;
    /// Base field — equal to the suite's proving field.
    type Base: PrimeField;
    /// Scalar field (the curve's group order). `Zeroize` so a secret scalar
    /// (a signing / exchange key) can be wiped — see
    /// [`SecretScalar`](crate::protocol::key::SecretScalar).
    type Scalar: PrimeField + Zeroize;

    /// The standard generator.
    fn generator() -> Self::Group {
        Self::Group::generator()
    }

    /// `[scalar]·G`.
    fn mul_generator(scalar: &Self::Scalar) -> Self::Group {
        Self::generator().mul_bigint(scalar.into_bigint())
    }
}

/// Affine point of an embedded curve.
pub type Affine<C> = <<C as EmbeddedCurve>::Group as CurveGroup>::Affine;

/// Affine `(x, y)` as native field elements, rejecting the identity.
pub fn coords<C: EmbeddedCurve>(p: &Affine<C>) -> Result<(C::Base, C::Base), Error> {
    let (x, y) = p.xy().ok_or(Error::Identity("curve point coords"))?;
    Ok((x, y))
}

/// Reinterpret a base-field element as a scalar (canonical for the
/// BN254/Grumpkin cycle: `r < q`, so the reduction is a no-op and the
/// map is injective). Used to turn a Poseidon challenge into a scalar.
pub fn base_to_scalar<C: EmbeddedCurve>(x: &C::Base) -> C::Scalar {
    C::Scalar::from_le_bytes_mod_order(&x.into_bigint().to_bytes_le())
}

// ----------------------------------------------------------------------
// Grumpkin instance (BN254's embedded curve).
// ----------------------------------------------------------------------

/// Grumpkin: base field = `ark_bn254::Fr`, scalar field = `ark_bn254::Fq`.
pub struct Grumpkin;

impl EmbeddedCurve for Grumpkin {
    type Group = ark_grumpkin::Projective;
    type Base = ark_grumpkin::Fq; // == ark_bn254::Fr
    type Scalar = ark_grumpkin::Fr;
}
