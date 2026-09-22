//! Fingerprint-service epoch entry — canonical bytes and digest.
//!
//! An [`FsEpoch`] describes one epoch of the fingerprint-service attestation
//! committee: the epoch number, the committee's threshold public key on
//! BLS12-381 G2, the hash-to-curve domain separation tag its signatures use,
//! the first working day the epoch covers, a hash of the member set, and the
//! digest of the preceding epoch. Epochs form a hash chain: a successor's
//! `prev_hash` equals its predecessor's [`FsEpoch::digest`], and a
//! [`SignedFsEpoch`] carries the predecessor committee's signature over the
//! successor's digest.
//!
//! That signature authenticates the handoff only while the predecessor's
//! `pk_att` is used solely to sign. A BLS key that also serves as a blind
//! evaluator returns `[k]·B` for any client-supplied point `B`, so a client
//! that submits `B = H2C(successor.digest(), dst_prev)` as its blinded point
//! receives a valid `sig_prev` for an entry of its own choosing; the
//! domain separation tag does not help, because the client hashes to the
//! curve itself. The chain is therefore exactly as strong as each committee's
//! non-use of `pk_att` as a raw-point evaluator, and a verifier that accepts
//! a successor on `sig_prev` alone relies on that property.
//!
//! This encoding is consensus data: the fingerprint service produces it, the
//! L2 node relays it, and the L2 contracts recompute the digest on-chain
//! before accepting an epoch. It is plain big-endian bytes plus keccak-256
//! and takes no `Suite` parameter — nothing here depends on the swappable
//! curve, field hash, or signature scheme.
//!
//! # ABI
//!
//! Canonical bytes, all integers big-endian, no ABI headers or padding:
//!
//! ```text
//! u8  EPOCH_ENCODING_VERSION   (= 1)
//! u32 epoch
//! [u8; 256] pk_att             (BLS12-381 G2, EIP-2537 layout)
//! u8  len(dst)                 (1..=255)
//! dst
//! u32 start_wwd                (YYYYMMDD)
//! [u8; 32] members_hash
//! [u8; 32] prev_hash
//! ```
//!
//! `digest = keccak256(canonical_bytes)`.
//!
//! Solidity must reproduce this with
//! `abi.encodePacked(uint8(1), uint32(epoch), pkAtt, uint8(dst.length), dst,
//! uint32(startWwd), membersHash, prevHash)`, and a successor's `prev_hash`
//! equals its predecessor's digest. The contract must first
//! `require(pkAtt.length == 256 && dst.length >= 1 && dst.length <= 255 &&
//! keccak256(pkAtt) != keccak256(new bytes(256)))` and, for each of the four
//! 64-byte limbs of `pkAtt`, `require(bytes16(pkAtt[i * 64:i * 64 + 16]) == 0)`.
//! `uint8(dst.length)` truncates silently, so a 256-byte `dst` would encode a
//! zero length byte and hash to a digest this crate never produces. The
//! EIP-2537 precompile accepts the all-zero encoding as the point at infinity
//! and errors on non-zero limb padding, but only when the key is used, so a
//! contract that stores `pkAtt` without exercising it rejects both itself.
//! With these five checks the contract rejects exactly what [`FsEpoch::new`]
//! rejects. Field canonicality (each limb `< p`), on-curve and subgroup
//! membership are checked on neither side here; the pairing precompile
//! enforces them when the key is used, so a verifier that stores `pkAtt`
//! without exercising it must accept that the next handoff can revert.
//!
//! `pk_att` uses the EIP-2537 G2 point layout: `x.c0`, `x.c1`, `y.c0`, `y.c1`,
//! each a 64-byte big-endian field element with 16 leading zero bytes.
//! [`FsEpoch::new`] and [`FsEpoch::decode`] reject non-zero padding and the
//! all-zero encoding, which EIP-2537 reads as the point at infinity and under
//! which every signature is trivially satisfiable; whether the coordinates
//! are on the curve and in the prime-order subgroup is the verifier's check.
//! A [`SignedFsEpoch::sig_prev`] is a G1 point in the same convention: `x`,
//! `y`, each 64 bytes big-endian with 16 leading zero bytes.
//!
//! `tests/fixtures/fs_epoch_parity.json` pins vectors of this encoding; the
//! L2 contracts' parity test consumes the same file.

use sha3::{Digest, Keccak256};

/// Byte length of a BLS12-381 G2 point in EIP-2537 layout.
pub const G2_EIP2537_LEN: usize = 256;

/// Byte length of a BLS12-381 G1 point in EIP-2537 layout.
pub const G1_EIP2537_LEN: usize = 128;

/// Version byte leading every canonical encoding.
pub const EPOCH_ENCODING_VERSION: u8 = 1;

/// Longest domain separation tag the one-byte length prefix can carry.
pub const MAX_DST_LEN: usize = u8::MAX as usize;

/// Byte length of one EIP-2537 field-element limb.
const LIMB_LEN: usize = 64;

/// Zero padding leading every EIP-2537 limb.
const LIMB_PAD: [u8; 16] = [0; 16];

/// Byte length of the fixed part of the encoding (everything but `dst`).
const FIXED_LEN: usize = 1 + 4 + G2_EIP2537_LEN + 1 + 4 + 32 + 32;

/// Why an epoch entry cannot be built or decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FsEpochError {
    /// `dst` is empty.
    #[error("empty domain separation tag")]
    EmptyDst,
    /// `dst` is longer than [`MAX_DST_LEN`] bytes.
    #[error("domain separation tag longer than 255 bytes")]
    DstTooLong,
    /// `pk_att` is all zero: the EIP-2537 point at infinity.
    #[error("pk_att is the point at infinity")]
    PkAttInfinity,
    /// A limb of `pk_att` has non-zero bytes in its 16-byte padding.
    #[error("pk_att limb padding is not zero")]
    PkAttPadding,
    /// The input is too short, or has trailing bytes after one encoding.
    #[error("malformed epoch encoding")]
    Malformed,
    /// The leading version byte is not [`EPOCH_ENCODING_VERSION`].
    #[error("unsupported epoch encoding version {0}")]
    UnsupportedVersion(u8),
}

/// One fingerprint-service epoch entry.
///
/// Every value of this type is encodable: [`FsEpoch::new`] and
/// [`FsEpoch::decode`] are the only constructors and both reject a `dst` the
/// one-byte length prefix cannot carry and a `pk_att` that is not a padded
/// EIP-2537 G2 encoding, so [`canonical_bytes`](Self::canonical_bytes) and
/// [`digest`](Self::digest) cannot fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsEpoch {
    epoch: u32,
    pk_att: [u8; G2_EIP2537_LEN],
    dst: Vec<u8>,
    start_wwd: u32,
    members_hash: [u8; 32],
    prev_hash: [u8; 32],
}

impl FsEpoch {
    /// Build an entry, checking the bounds the encoding relies on.
    ///
    /// # Errors
    ///
    /// [`FsEpochError::EmptyDst`] or [`FsEpochError::DstTooLong`] for a `dst`
    /// the one-byte length prefix cannot carry; [`FsEpochError::PkAttInfinity`]
    /// for an all-zero `pk_att`; [`FsEpochError::PkAttPadding`] for non-zero
    /// bytes in a limb's 16-byte padding.
    pub fn new(
        epoch: u32,
        pk_att: [u8; G2_EIP2537_LEN],
        dst: Vec<u8>,
        start_wwd: u32,
        members_hash: [u8; 32],
        prev_hash: [u8; 32],
    ) -> Result<Self, FsEpochError> {
        if dst.is_empty() {
            return Err(FsEpochError::EmptyDst);
        }
        if dst.len() > MAX_DST_LEN {
            return Err(FsEpochError::DstTooLong);
        }
        if pk_att.iter().all(|&b| b == 0) {
            return Err(FsEpochError::PkAttInfinity);
        }
        if pk_att.chunks(LIMB_LEN).any(|limb| limb[..16] != LIMB_PAD) {
            return Err(FsEpochError::PkAttPadding);
        }
        Ok(Self {
            epoch,
            pk_att,
            dst,
            start_wwd,
            members_hash,
            prev_hash,
        })
    }

    /// Epoch number; the genesis entry is epoch 0 with an all-zero
    /// `prev_hash`.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Committee threshold public key: BLS12-381 G2 in EIP-2537 layout.
    pub fn pk_att(&self) -> &[u8; G2_EIP2537_LEN] {
        &self.pk_att
    }

    /// Hash-to-curve domain separation tag the committee signs under;
    /// non-empty, at most [`MAX_DST_LEN`] bytes.
    pub fn dst(&self) -> &[u8] {
        &self.dst
    }

    /// First working day of the epoch, nominally `YYYYMMDD`; this crate
    /// carries the value opaquely and does not validate it.
    pub fn start_wwd(&self) -> u32 {
        self.start_wwd
    }

    /// Hash of the committee member set.
    pub fn members_hash(&self) -> &[u8; 32] {
        &self.members_hash
    }

    /// Digest of the preceding epoch entry.
    pub fn prev_hash(&self) -> &[u8; 32] {
        &self.prev_hash
    }

    /// Canonical encoding as described in the module ABI.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FIXED_LEN + self.dst.len());
        out.push(EPOCH_ENCODING_VERSION);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.pk_att);
        out.push(self.dst.len() as u8);
        out.extend_from_slice(&self.dst);
        out.extend_from_slice(&self.start_wwd.to_be_bytes());
        out.extend_from_slice(&self.members_hash);
        out.extend_from_slice(&self.prev_hash);
        out
    }

    /// `keccak256(canonical_bytes)`.
    pub fn digest(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Keccak256::digest(self.canonical_bytes()));
        out
    }

    /// Parse exactly one canonical encoding; trailing bytes are rejected and
    /// the decoded fields pass the same checks as [`new`](Self::new).
    ///
    /// # Errors
    ///
    /// [`FsEpochError::UnsupportedVersion`] when the leading byte is not
    /// [`EPOCH_ENCODING_VERSION`]; [`FsEpochError::Malformed`] when the input
    /// is too short or has trailing bytes; otherwise whatever
    /// [`new`](Self::new) returns for the decoded fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, FsEpochError> {
        let (&version, rest) = bytes.split_first().ok_or(MALFORMED)?;
        if version != EPOCH_ENCODING_VERSION {
            return Err(FsEpochError::UnsupportedVersion(version));
        }
        let (epoch, rest) = take_u32(rest)?;
        let (pk_att, rest) = take_array::<G2_EIP2537_LEN>(rest)?;
        let (&dst_len, rest) = rest.split_first().ok_or(MALFORMED)?;
        let (dst, rest) = take(rest, usize::from(dst_len))?;
        let (start_wwd, rest) = take_u32(rest)?;
        let (members_hash, rest) = take_array::<32>(rest)?;
        let (prev_hash, rest) = take_array::<32>(rest)?;
        if !rest.is_empty() {
            return Err(MALFORMED);
        }
        Self::new(
            epoch,
            pk_att,
            dst.to_vec(),
            start_wwd,
            members_hash,
            prev_hash,
        )
    }
}

/// An epoch entry with the predecessor committee's signature over it.
///
/// The type carries the pair as given. A verifier must reject
/// `entry.epoch() == 0` (the genesis entry has no predecessor and is pinned
/// out of band) and an all-zero `sig_prev` (the G1 point at infinity, which
/// satisfies a bare pairing check against any message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFsEpoch {
    /// The epoch entry.
    pub entry: FsEpoch,
    /// BLS12-381 G1 signature in EIP-2537 layout by the previous epoch's
    /// threshold key, over [`signing_message`] of `entry` and under the
    /// previous epoch's `dst`. It proves the handoff only if that key is never
    /// used as a raw-point evaluator (see the module docs).
    pub sig_prev: [u8; G1_EIP2537_LEN],
}

/// The 32 bytes the previous epoch's threshold key signs: `entry.digest()`.
///
/// The signature is produced under the previous epoch's `dst`, so a verifier
/// hashes these bytes to G1 with the predecessor's tag, not the successor's.
pub fn signing_message(entry: &FsEpoch) -> [u8; 32] {
    entry.digest()
}

const MALFORMED: FsEpochError = FsEpochError::Malformed;

fn take(bytes: &[u8], n: usize) -> Result<(&[u8], &[u8]), FsEpochError> {
    if bytes.len() < n {
        return Err(MALFORMED);
    }
    Ok(bytes.split_at(n))
}

fn take_array<const N: usize>(bytes: &[u8]) -> Result<([u8; N], &[u8]), FsEpochError> {
    let (head, rest) = take(bytes, N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(head);
    Ok((out, rest))
}

fn take_u32(bytes: &[u8]) -> Result<(u32, &[u8]), FsEpochError> {
    let (head, rest) = take_array::<4>(bytes)?;
    Ok((u32::from_be_bytes(head), rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A padded, non-zero G2 encoding: every limb has 16 zero bytes then a
    /// distinct non-zero tail.
    fn padded_pk() -> [u8; G2_EIP2537_LEN] {
        core::array::from_fn(|i| if i % LIMB_LEN < 16 { 0 } else { i as u8 })
    }

    fn sample() -> FsEpoch {
        FsEpoch::new(
            7,
            padded_pk(),
            b"PSO-FS-EPOCH-V1-TEST".to_vec(),
            20260921,
            [0xAB; 32],
            [0xCD; 32],
        )
        .unwrap()
    }

    #[test]
    fn round_trip() {
        let entry = sample();
        let bytes = entry.canonical_bytes();
        assert_eq!(bytes.len(), FIXED_LEN + entry.dst().len());
        assert_eq!(bytes[0], EPOCH_ENCODING_VERSION);
        assert_eq!(FsEpoch::decode(&bytes).unwrap(), entry);
        let signed = SignedFsEpoch {
            entry: entry.clone(),
            sig_prev: [1; G1_EIP2537_LEN],
        };
        assert_eq!(signing_message(&signed.entry), entry.digest());
        assert!(matches!(
            crate::Error::from(FsEpochError::EmptyDst),
            crate::Error::Epoch(FsEpochError::EmptyDst)
        ));
        assert_eq!(entry.epoch(), 7);
        assert_eq!(entry.pk_att(), &padded_pk());
        assert_eq!(entry.start_wwd(), 20260921);
        assert_eq!(entry.members_hash(), &[0xAB; 32]);
        assert_eq!(entry.prev_hash(), &[0xCD; 32]);
    }

    /// Pinned output for one fixed vector: the L2 contracts compute the same
    /// value from `abi.encodePacked`, so this hex changes only when the
    /// encoding does.
    #[test]
    fn digest_is_stable() {
        let hex: String = sample()
            .digest()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "7be3f7d5e3ddb3cb30456851466c071decdbc9018060979fb287865e510cd8d3"
        );
    }

    #[test]
    fn dst_bounds() {
        let with_dst =
            |dst: Vec<u8>| FsEpoch::new(7, padded_pk(), dst, 20260921, [0xAB; 32], [0xCD; 32]);
        assert_eq!(with_dst(vec![]), Err(FsEpochError::EmptyDst));
        assert_eq!(
            with_dst(vec![0x41; MAX_DST_LEN + 1]),
            Err(FsEpochError::DstTooLong)
        );
        let max = with_dst(vec![0x41; MAX_DST_LEN]).unwrap();
        assert_eq!(FsEpoch::decode(&max.canonical_bytes()).unwrap(), max);
    }

    #[test]
    fn pk_att_layout() {
        let with_pk =
            |pk_att| FsEpoch::new(7, pk_att, b"x".to_vec(), 20260921, [0xAB; 32], [0xCD; 32]);
        assert_eq!(
            with_pk([0; G2_EIP2537_LEN]),
            Err(FsEpochError::PkAttInfinity)
        );
        let mut bad_pad = padded_pk();
        bad_pad[3 * LIMB_LEN + 15] = 1;
        assert_eq!(with_pk(bad_pad), Err(FsEpochError::PkAttPadding));

        // The same checks run on decoded bytes.
        let mut bytes = sample().canonical_bytes();
        bytes[1 + 4 + LIMB_LEN] = 1;
        assert_eq!(FsEpoch::decode(&bytes), Err(FsEpochError::PkAttPadding));
        bytes[1 + 4..1 + 4 + G2_EIP2537_LEN].fill(0);
        assert_eq!(FsEpoch::decode(&bytes), Err(FsEpochError::PkAttInfinity));
    }

    #[test]
    fn decode_rejects_bad_input() {
        let entry = sample();
        let bytes = entry.canonical_bytes();
        let malformed = Err(FsEpochError::Malformed);
        let dst_len_at = 1 + 4 + G2_EIP2537_LEN;

        assert_eq!(FsEpoch::decode(&[]), malformed);
        assert_eq!(FsEpoch::decode(&bytes[..bytes.len() - 1]), malformed);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(FsEpoch::decode(&trailing), malformed);

        // The length byte claims more dst bytes than the input holds.
        let mut long_dst = bytes.clone();
        long_dst[dst_len_at] = 0xFF;
        assert_eq!(FsEpoch::decode(&long_dst), malformed);

        // A zero length byte with no dst bytes parses and is refused by `new`.
        let mut zero_dst = bytes.clone();
        zero_dst[dst_len_at] = 0;
        zero_dst.drain(dst_len_at + 1..dst_len_at + 1 + entry.dst().len());
        assert_eq!(FsEpoch::decode(&zero_dst), Err(FsEpochError::EmptyDst));

        let mut wrong_version = bytes.clone();
        wrong_version[0] = 2;
        assert_eq!(
            FsEpoch::decode(&wrong_version),
            Err(FsEpochError::UnsupportedVersion(2))
        );
    }
}
