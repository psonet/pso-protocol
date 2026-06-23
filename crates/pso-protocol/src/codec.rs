//! Codec: how typed values cross between the protocol's field/curve world and
//! bytes.
//!
//! Two layers live here:
//!
//! 1. **Field encoding** ([`FieldElement`] / [`FieldEncode`]) — how a typed
//!    entity member folds into native field elements. The protocol hashes over
//!    `S::Field`, but an entity is a struct with named, typed members (an
//!    address, a `uint256`, a stored field id, …):
//!    - [`FieldElement`] — a value occupying **exactly one** field element (an
//!      address, a `bytes32` that is itself a field value, a small integer).
//!      Usable as an entity's id seed.
//!    - [`FieldEncode`] — a value expanding into **zero or more** field elements
//!      in canonical order (a `uint256` → two 128-bit limbs, a `T[]` → its
//!      elements). Everything in an entity body is `FieldEncode`.
//!
//!    Encoding is **fallible**: there is no safe total map from arbitrary
//!    256-bit bytes onto a ~254-bit field. A `bytes32` whose value is `>=` the
//!    modulus has no canonical element, and silently reducing it (`mod_order`)
//!    would alias distinct byte strings onto the same element — breaking the
//!    on-chain ↔ in-circuit binding. So a checked decode returns
//!    [`Error::NonCanonical`]. Use [`field_from_be_bytes_canonical`] for a value
//!    that *is* a field element; the plain [`field_from_be_bytes`] reducer is
//!    only for inputs already smaller than the modulus (e.g. a 20-byte address).
//!
//! 2. **Byte (de)serialization** ([`Codec`]) — a suite's field elements and
//!    embedded-curve keys ↔ their canonical byte forms, with key blocks sized
//!    at the type level (`Codec::Bytes`). Blanket conventions every FFI / chain
//!    boundary uses; bring it into scope with `use pso_protocol::Codec`.

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use generic_array::typenum::U32;
use generic_array::{ArrayLength, GenericArray};

use crate::error::Error;
use crate::primitive::curve::{Affine, EmbeddedCurve};
use crate::suite::Suite;

// ============================ field encoding ============================

/// A value that occupies exactly one field element.
///
/// This is the stricter half of [`FieldEncode`]: a `FieldElement` is a
/// single element, so it can seed an entity id (`Entity::id_seed`) where
/// a multi-element value cannot.
pub trait FieldElement<F: PrimeField> {
    /// The single field element this value encodes to, or
    /// [`Error::NonCanonical`] if it has no canonical element.
    fn to_field(&self) -> Result<F, Error>;
}

/// A value that encodes into zero or more field elements, in canonical
/// order, appended to `out`.
pub trait FieldEncode<F: PrimeField> {
    /// Append this value's field elements to `out`, or fail with
    /// [`Error::NonCanonical`] if some member has no canonical element.
    fn encode(&self, out: &mut Vec<F>) -> Result<(), Error>;
}

/// Decode big-endian bytes as one field element, **reducing mod the field
/// order**. Only safe for inputs guaranteed smaller than the modulus
/// (e.g. a ≤20-byte address); for a full-width value that must be a field
/// element use [`field_from_be_bytes_canonical`].
pub fn field_from_be_bytes<F: PrimeField>(bytes: &[u8]) -> F {
    F::from_be_bytes_mod_order(bytes)
}

/// Decode big-endian bytes as one field element, **rejecting** a value
/// that is not already canonical (`>=` the field modulus). This is the
/// safe decode for a `bytes32` that carries a field element (an id, a
/// `derivedOwner`): a non-canonical input would otherwise be silently
/// reduced onto a different element.
pub fn field_from_be_bytes_canonical<F: PrimeField>(
    bytes: &[u8],
    what: &'static str,
) -> Result<F, Error> {
    // Parse the big-endian bytes into the field's big-integer repr, then let
    // `from_bigint` do the canonical check: it compares `repr < modulus` and
    // returns `None` for anything `>= p` (no silent reduction, no byte
    // comparison).
    let bits: Vec<bool> = bytes
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect();
    let repr = <F::BigInt as BigInteger>::from_bits_be(&bits);
    F::from_bigint(repr).ok_or(Error::NonCanonical(what))
}

/// Split a big-endian `uint256` into canonical `[lo, hi]` 128-bit limbs —
/// the same split [`crate::suite::Suite::binding`] applies to a
/// `commitmentId`. A 256-bit value does not fit one field element, so it
/// is always carried as this two-limb pair. Each limb is 128 bits, always
/// smaller than the modulus, so this is total (never aliases).
pub fn u256_limbs_be<F: PrimeField>(be32: &[u8; 32]) -> [F; 2] {
    let lo = F::from_be_bytes_mod_order(&be32[16..32]);
    let hi = F::from_be_bytes_mod_order(&be32[0..16]);
    [lo, hi]
}

// ---- primitive integers / bool: one element each ----
//
// Note there is deliberately no blanket `impl FieldElement<F> for F`: by
// coherence it would overlap these (the compiler must assume an integer
// could become a `PrimeField`). Generic code holding a bare `S::Field`
// pushes it directly; the field-valued members of a consumer's entity
// (an id, a `derivedOwner`) arrive as a `bytes32`-style type whose impl
// lives with that type.

macro_rules! scalar_field_element {
    ($($t:ty),*) => {$(
        impl<F: PrimeField> FieldElement<F> for $t {
            fn to_field(&self) -> Result<F, Error> { Ok(F::from(*self)) }
        }
        impl<F: PrimeField> FieldEncode<F> for $t {
            fn encode(&self, out: &mut Vec<F>) -> Result<(), Error> {
                out.push(F::from(*self));
                Ok(())
            }
        }
    )*};
}
scalar_field_element!(u8, u16, u32, u64, u128, bool);

/// An entity vector field viewed as a canonical **set**.
///
/// A bare `[T]`/`Vec<T>` [`FieldEncode`] just concatenates its elements (see
/// below), which is ambiguous for an entity hash: two adjacent vectors
/// `sr = [a]`, `ar = [b, c]` fold to the *same* preimage as `sr = [a, b]`,
/// `ar = [c]` (a boundary collision), and the same multiset in a different
/// order folds to a different hash.
///
/// Wrapping a slice in `SortedSet` gives it a `FieldEncode` impl that removes
/// both ambiguities — so it composes into the same trait as every other field
/// instead of needing a bespoke call. `#[derive(Entity)]` wraps a `Vec<T>`
/// body field in this automatically; the underlying `[T]` impl is left as the
/// plain concatenation for any non-entity use. It is a zero-cost view (a
/// single `&[T]`).
pub struct SortedSet<'a, T>(pub &'a [T]);

impl<F: PrimeField, T: FieldElement<F>> FieldEncode<F> for SortedSet<'_, T> {
    /// Emit `[ len, e₀, e₁, … ]` with the elements strictly ascending by field
    /// value. The length prefix makes the boundary between two adjacent vectors
    /// unambiguous; the strict order makes the encoding canonical
    /// (origin-order–independent) *and* duplicate-free in one check.
    ///
    /// It does **not** sort for the caller: the input must already be sorted
    /// and de-duplicated, and a violation is rejected with
    /// [`Error::UnsortedSet`]. Requiring sorted input (rather than sorting
    /// here) keeps this in lock-step with the in-circuit fold, which asserts
    /// the same `eᵢ < eᵢ₊₁`, and forces every producer (chain, mobile, tests)
    /// to commit the same canonical order on-chain.
    fn encode(&self, out: &mut Vec<F>) -> Result<(), Error> {
        out.push(F::from(self.0.len() as u64));
        // Field elements are stored in Montgomery form, whose limb order is not
        // the value order, so the strict-ascending check must compare canonical
        // big-integer reprs (this is exactly what `ark`'s own `Ord for Fp` does
        // internally). Convert each element to its `BigInt` once and keep it as
        // `prev` — `F::BigInt: Ord` via `BigInteger`, so no `Ord` bound on `F`
        // and no second conversion per comparison.
        let mut prev: Option<F::BigInt> = None;
        for item in self.0 {
            let f = item.to_field()?;
            let cur = f.into_bigint();
            if let Some(p) = prev {
                // Reject anything not *strictly* greater — catches both
                // unsorted input and duplicate elements in one check.
                if cur <= p {
                    return Err(Error::UnsortedSet(
                        "entity vector field must be strictly ascending by field value (sorted + de-duplicated)".to_string(),
                    ));
                }
            }
            out.push(f);
            prev = Some(cur);
        }
        Ok(())
    }
}

// ---- containers: encode each element in order ----

impl<F: PrimeField, T: FieldEncode<F> + ?Sized> FieldEncode<F> for &T {
    fn encode(&self, out: &mut Vec<F>) -> Result<(), Error> {
        (*self).encode(out)
    }
}
impl<F: PrimeField, T: FieldEncode<F>> FieldEncode<F> for [T] {
    fn encode(&self, out: &mut Vec<F>) -> Result<(), Error> {
        for x in self {
            x.encode(out)?;
        }
        Ok(())
    }
}
impl<F: PrimeField, T: FieldEncode<F>> FieldEncode<F> for Vec<T> {
    fn encode(&self, out: &mut Vec<F>) -> Result<(), Error> {
        self.as_slice().encode(out)
    }
}
impl<F: PrimeField, T: FieldEncode<F>, const N: usize> FieldEncode<F> for [T; N] {
    fn encode(&self, out: &mut Vec<F>) -> Result<(), Error> {
        self.as_slice().encode(out)
    }
}

// ---- alloy ABI scalar types (behind the `alloy` feature) ----
//
// These impls live here, not in a consumer crate, because the orphan rule
// forbids `impl FieldEncode for alloy::Address` anywhere but the trait's
// own crate. They mirror the Solidity → field convention exactly:
// `address`/`bytes32` are single elements, `uint256` is a two-limb pair.
#[cfg(feature = "alloy")]
mod alloy_impls {
    use super::{
        field_from_be_bytes, field_from_be_bytes_canonical, u256_limbs_be, Error, FieldElement,
        FieldEncode,
    };
    use alloy_primitives::{Address, FixedBytes, U16, U256, U32, U64};
    use ark_ff::PrimeField;

    // `address` — 160 bits, always < the field modulus, so total.
    impl<F: PrimeField> FieldElement<F> for Address {
        fn to_field(&self) -> Result<F, Error> {
            Ok(field_from_be_bytes(self.as_slice()))
        }
    }
    impl<F: PrimeField> FieldEncode<F> for Address {
        fn encode(&self, out: &mut Vec<F>) -> Result<(), Error> {
            out.push(FieldElement::to_field(self)?);
            Ok(())
        }
    }

    // `bytes32` carrying a field element (an id, a `derivedOwner`):
    // decoded canonically, rejecting a value >= the modulus.
    impl<F: PrimeField> FieldElement<F> for FixedBytes<32> {
        fn to_field(&self) -> Result<F, Error> {
            field_from_be_bytes_canonical(self.as_slice(), "bytes32")
        }
    }
    impl<F: PrimeField> FieldEncode<F> for FixedBytes<32> {
        fn encode(&self, out: &mut Vec<F>) -> Result<(), Error> {
            out.push(FieldElement::to_field(self)?);
            Ok(())
        }
    }

    // `uintN` for N <= 64 — one 64-bit limb, always < the field modulus,
    // so a single element.
    macro_rules! uint_one_limb {
        ($($t:ty),*) => {$(
            impl<F: PrimeField> FieldElement<F> for $t {
                fn to_field(&self) -> Result<F, Error> {
                    Ok(F::from(self.as_limbs()[0]))
                }
            }
            impl<F: PrimeField> FieldEncode<F> for $t {
                fn encode(&self, out: &mut Vec<F>) -> Result<(), Error> {
                    out.push(FieldElement::to_field(self)?);
                    Ok(())
                }
            }
        )*};
    }
    uint_one_limb!(U16, U32, U64);

    // `uint256` — two 128-bit limbs `[lo, hi]`. Intentionally not a
    // `FieldElement`, so it can't seed an id or be an owner.
    impl<F: PrimeField> FieldEncode<F> for U256 {
        fn encode(&self, out: &mut Vec<F>) -> Result<(), Error> {
            out.extend(u256_limbs_be::<F>(&self.to_be_bytes::<32>()));
            Ok(())
        }
    }
}

// ====================== byte (de)serialization ==========================

/// A suite's embedded-curve secret scalar (a signing / NFT / consent key).
pub type Secret<S> = <<S as Suite>::Curve as EmbeddedCurve>::Scalar;
/// A suite's embedded-curve public key (affine point).
pub type PublicKey<S> = Affine<<S as Suite>::Curve>;
/// A suite's canonical fixed-size byte block (serialized key), sized by the type.
pub type KeyBytes<S> = GenericArray<u8, <S as Codec>::Bytes>;

/// Compress `t` into a `GenericArray<u8, N>`, fallibly — no panic. Serializes
/// into a growable `Vec` (can't overflow, won't silently zero-pad like a fixed
/// slice), then checks the length is exactly `N` (`Codec::Bytes` must equal the
/// key's compressed size) before the infallible `from_slice`. A misconfigured
/// size surfaces as an `Err`, not a panic.
fn serialize<T: CanonicalSerialize, N: ArrayLength>(t: &T) -> Result<GenericArray<u8, N>, Error> {
    let mut buf = Vec::with_capacity(N::USIZE);
    t.serialize_compressed(&mut buf)
        .map_err(|_| Error::Signature("serialize failed"))?;
    if buf.len() != N::USIZE {
        return Err(Error::Signature("serialized length != Codec::Bytes"));
    }
    Ok(GenericArray::from_slice(&buf).clone())
}

/// Canonical byte (de)serialization for a [`Suite`]'s field and embedded-curve
/// keys, with key blocks sized at the type level (`Codec::Bytes`). Implemented
/// per suite (see `impl Codec for PsoV1`).
///
/// Direction matters for copies: byte *outputs* are typed
/// `GenericArray<u8, Bytes>` (sized, stack); byte *inputs* are `&[u8]`, because
/// they arrive from untyped runtime buffers (FFI `Vec<u8>`) and the decode
/// itself validates the length. A `Vec` is materialized only at the actual
/// boundary (one `.to_vec()`), never in between.
pub trait Codec: Suite {
    /// Type-level serialized byte length of the field / embedded-curve keys
    /// (e.g. `U32` for the BN254/Grumpkin stack).
    type Bytes: ArrayLength;

    /// Field element → owned big-endian `Vec` (size-agnostic; the form values
    /// take crossing an FFI boundary, one allocation).
    fn field_to_be_bytes(f: &Self::Field) -> Vec<u8> {
        f.into_bigint().to_bytes_be()
    }

    /// 32-byte big-endian → field element (reduced mod order).
    fn field_from_be32(b: &[u8; 32]) -> Self::Field {
        Self::Field::from_be_bytes_mod_order(b)
    }

    /// Embedded-curve secret scalar → its type-sized byte block.
    fn secret_to_bytes(s: &Secret<Self>) -> Result<GenericArray<u8, Self::Bytes>, Error> {
        serialize(s)
    }

    /// Bytes → embedded-curve secret scalar (length validated by the decode).
    fn secret_from_bytes(b: &[u8]) -> Result<Secret<Self>, Error> {
        Secret::<Self>::deserialize_compressed(b).map_err(|_| Error::Signature("bad scalar"))
    }

    /// Public key from its secret: `pk = sk·G` on the embedded curve.
    fn public_key_from_secret(sk: &Secret<Self>) -> PublicKey<Self> {
        Self::Curve::mul_generator(sk).into_affine()
    }

    /// Public key → its compressed, type-sized byte block.
    fn public_key_to_bytes(p: &PublicKey<Self>) -> Result<GenericArray<u8, Self::Bytes>, Error> {
        serialize(p)
    }

    /// Bytes → public key (length validated by the decode).
    fn public_key_from_bytes(b: &[u8]) -> Result<PublicKey<Self>, Error> {
        PublicKey::<Self>::deserialize_compressed(b).map_err(|_| Error::Signature("bad public key"))
    }
}

impl Codec for crate::PsoV1 {
    type Bytes = U32;
}
