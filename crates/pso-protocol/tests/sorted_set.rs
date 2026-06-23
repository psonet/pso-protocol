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

/// `sort_set` is the producer-side normaliser: it turns an arbitrary-order
/// input into exactly the order `SortedSet` asserts, so a producer can never
/// trip `UnsortedSet` on ordering. Feeding its output to the hash always
/// succeeds, and any permutation of the same set hashes identically.
#[test]
fn sort_set_normalises_for_the_encoder() {
    use pso_protocol::codec::sort_set;
    type F = <PsoV1 as pso_protocol::Suite>::Field;

    // Arbitrary order in → ascending out.
    let sorted = sort_set::<F, u64>(&[30, 10, 20]).unwrap();
    assert_eq!(sorted, vec![10, 20, 30]);

    // Its output sails through the strict-ascending encoder...
    let from_unsorted = hash(1, &sort_set::<F, u64>(&[30, 10, 20]).unwrap(), &[]).unwrap();
    // ...and equals the hash of the already-sorted set (order-independent).
    assert_eq!(from_unsorted, hash(1, &[10, 20, 30], &[]).unwrap());
    assert_eq!(
        from_unsorted,
        hash(1, &sort_set::<F, u64>(&[20, 30, 10]).unwrap(), &[]).unwrap(),
    );
}

/// `sort_set` collapses duplicates — a set is unique by definition — and its
/// output still sails through the strict-ascending encoder.
#[test]
fn sort_set_removes_duplicates() {
    use pso_protocol::codec::sort_set;
    type F = <PsoV1 as pso_protocol::Suite>::Field;

    assert_eq!(sort_set::<F, u64>(&[10, 20, 10, 20, 10]).unwrap(), vec![10, 20]);
    // De-duped output hashes fine, and equals the same set passed cleanly.
    let deduped = sort_set::<F, u64>(&[30, 10, 10, 20, 30]).unwrap();
    assert_eq!(deduped, vec![10, 20, 30]);
    assert_eq!(hash(1, &deduped, &[]).unwrap(), hash(1, &[10, 20, 30], &[]).unwrap());
}
