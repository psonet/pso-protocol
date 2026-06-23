//! Canonical **set** encoding for entity `Vec<T>` fields.
//!
//! A bare `Vec<T>` `FieldEncode` just concatenates its elements, which is
//! ambiguous inside an entity preimage in two ways:
//!
//! 1. **Boundary collision** — two adjacent vectors `sr = [a]`, `ar = [b, c]`
//!    flatten to the *same* `[a, b, c]` as `sr = [a, b]`, `ar = [c]`, so two
//!    structurally different entities share a hash.
//! 2. **Order ambiguity** — the same multiset in a different producer-order
//!    folds to a different hash.
//!
//! `#[derive(Entity)]` now routes a `Vec<T>` field through
//! [`pso_protocol::codec::SortedSet`], which folds `[len, e₀, e₁, …]`
//! with the elements strictly ascending. The length prefix kills (1); the
//! required ordering kills (2) and rejects duplicates.

use pso_protocol::error::Error;
use pso_protocol::protocol::entity::Entity as EntityTrait;
use pso_protocol::PsoV1;
use pso_protocol_derive::Entity;

/// Two adjacent set-valued body fields — the exact shape (`SpendingUnit`'s
/// `sr` / `ar`) that motivated the fix.
#[derive(Entity)]
struct TwoSets {
    #[pso(id_seed)]
    id: u64,
    #[pso(body, pos = 0)]
    sr: Vec<u64>,
    #[pso(body, pos = 1)]
    ar: Vec<u64>,
}

fn hash(id: u64, sr: &[u64], ar: &[u64]) -> Result<<PsoV1 as pso_protocol::Suite>::Field, Error> {
    let e = TwoSets {
        id,
        sr: sr.to_vec(),
        ar: ar.to_vec(),
    };
    EntityTrait::<PsoV1>::entity_hash(&e)
}

/// The boundary collision is gone: re-partitioning the same flat sequence
/// across the two vectors yields a different entity hash.
#[test]
fn adjacent_vectors_do_not_collide() {
    let a = hash(1, &[10], &[20, 30]).unwrap();
    let b = hash(1, &[10, 20], &[30]).unwrap();
    assert_ne!(a, b, "re-partitioned adjacent set fields collided");

    // A degenerate split (empty vs. full) is also distinct — the length
    // prefix encodes the empty vector as `[0]`, not nothing.
    let c = hash(1, &[], &[10, 20, 30]).unwrap();
    assert_ne!(a, c);
    assert_ne!(b, c);
}

/// Same field elements, different *vector order* across the fields → distinct
/// hashes (the encoding is positional per field, set-canonical within a field).
#[test]
fn deterministic_and_field_sensitive() {
    let a = hash(7, &[10, 20], &[30, 40]).unwrap();
    assert_eq!(
        a,
        hash(7, &[10, 20], &[30, 40]).unwrap(),
        "not deterministic"
    );
    assert_ne!(
        a,
        hash(7, &[30, 40], &[10, 20]).unwrap(),
        "field-order insensitive"
    );
    assert_ne!(a, hash(8, &[10, 20], &[30, 40]).unwrap(), "id insensitive");
}

/// An unsorted vector is rejected — the caller must commit the canonical
/// order, the encoder never silently sorts.
#[test]
fn unsorted_input_is_rejected() {
    let err = hash(1, &[30, 10], &[]).unwrap_err();
    assert!(
        matches!(err, Error::UnsortedSet(_)),
        "expected UnsortedSet, got {err:?}"
    );
    // …and in the second field too, after a valid first field.
    let err = hash(1, &[10], &[40, 20]).unwrap_err();
    assert!(matches!(err, Error::UnsortedSet(_)), "got {err:?}");
}

/// A duplicate element is rejected by the same strict-ascending check (a set
/// has no repeats), so the encoding stays a true set.
#[test]
fn duplicate_element_is_rejected() {
    let err = hash(1, &[10, 10], &[]).unwrap_err();
    assert!(
        matches!(err, Error::UnsortedSet(_)),
        "expected UnsortedSet for duplicate, got {err:?}"
    );
}

/// A correctly sorted, de-duplicated input hashes successfully (the happy
/// path the producers must satisfy).
#[test]
fn sorted_unique_input_succeeds() {
    assert!(hash(1, &[1, 2, 3, 4], &[5, 6, 7]).is_ok());
    assert!(hash(1, &[], &[]).is_ok()); // both empty: `[0]` / `[0]`
}
