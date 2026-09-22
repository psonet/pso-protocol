//! Suite-generic protocol logic. Nothing here names a curve, a hash, or a
//! signature scheme concretely — everything goes through `S: Suite`. The one
//! exception is [`fs_epoch`]: a fixed byte encoding plus keccak-256 that the
//! L2 contracts reproduce verbatim, so it takes no suite parameter.

pub mod entity;
pub mod fs_epoch;
pub mod imt;
pub mod key;
pub mod zk;
