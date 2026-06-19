//! Swappable cryptographic primitives. Each is a trait plus one or more
//! instances; a [`crate::suite::Suite`] selects one of each.

pub mod curve;
pub mod exchange;
pub mod hash;
pub mod kdf;
pub mod signature;
