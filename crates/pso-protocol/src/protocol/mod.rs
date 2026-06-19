//! Suite-generic protocol logic. Nothing here names a curve, a hash, or a
//! signature scheme concretely — everything goes through `S: Suite`.

pub mod entity;
pub mod imt;
pub mod key;
pub mod zk;
