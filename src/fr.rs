//! BN254 `Fr` ↔ bytes helpers.
//!
//! These conversions are part of the on-chain binding surface: every
//! precompile and Solidity wrapper agrees on the **big-endian, 32-byte**
//! representation as the wire format, and on **little-endian, mod-order
//! reduction** for ingesting EVM-side values. Changing either is a
//! consensus-breaking change.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// Decode a 32-byte big-endian slot into `Fr`, reducing modulo the field
/// order. This matches the EVM convention: `bytes32` slots are big-endian
/// and may exceed the BN254 scalar modulus.
pub fn fr_from_be_bytes(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Decode a 32-byte little-endian slot into `Fr`, reducing modulo the
/// field order. Used by code paths that already work in LE (notably the
/// witness builders generated from secp256k1 coordinates).
pub fn fr_from_le_bytes(bytes: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

/// Encode `Fr` as 32 big-endian bytes (left-padded with zeros). This is
/// the on-chain wire format every PSO precompile returns.
pub fn fr_to_be_bytes(value: &Fr) -> [u8; 32] {
    let big = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let off = 32 - big.len().min(32);
    out[off..].copy_from_slice(&big[big.len().saturating_sub(32)..]);
    out
}

/// Encode `Fr` as 32 little-endian bytes (right-padded with zeros).
pub fn fr_to_le_bytes(value: &Fr) -> [u8; 32] {
    let big = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let n = big.len().min(32);
    out[..n].copy_from_slice(&big[..n]);
    out
}

/// Split a 32-byte big-endian uint256 into two 128-bit `Fr` limbs:
/// `[lo, hi]` where `lo` is the lower 128 bits and `hi` the upper 128.
///
/// This is the exact decomposition `TributeDraft._bindingHash` uses to
/// fit a `uint256` into two BN254 field elements without overflow.
///
/// **Not** the right helper for secp256k1 coordinates — those use a
/// different scheme (LE-decode each 16-byte half), implemented privately
/// in `ownership.rs`.
pub fn split_u256_be_into_limbs(bytes: &[u8; 32]) -> [Fr; 2] {
    let mut lo_le = [0u8; 32];
    for (i, b) in bytes[16..32].iter().rev().enumerate() {
        lo_le[i] = *b;
    }
    let mut hi_le = [0u8; 32];
    for (i, b) in bytes[0..16].iter().rev().enumerate() {
        hi_le[i] = *b;
    }
    [
        Fr::from_le_bytes_mod_order(&lo_le),
        Fr::from_le_bytes_mod_order(&hi_le),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn be_roundtrip_zero() {
        let zero = Fr::from(0u64);
        assert_eq!(fr_to_be_bytes(&zero), [0u8; 32]);
        assert_eq!(fr_from_be_bytes(&[0u8; 32]), zero);
    }

    #[test]
    fn be_roundtrip_small() {
        let v = Fr::from(0x1234_5678u64);
        let bytes = fr_to_be_bytes(&v);
        assert_eq!(&bytes[28..], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(fr_from_be_bytes(&bytes), v);
    }

    #[test]
    fn split_u256_lower_upper() {
        // bytes (big-endian uint256) = 0xAAAA...AAAA_BBBB...BBBB
        // where the upper 16 bytes are 0xAA and the lower 16 are 0xBB.
        let mut bytes = [0u8; 32];
        for b in bytes.iter_mut().take(16) {
            *b = 0xAA;
        }
        for b in bytes.iter_mut().skip(16) {
            *b = 0xBB;
        }
        let [lo, hi] = split_u256_be_into_limbs(&bytes);

        // lo encodes the 128-bit value 0xBBBB...BB. As a BE uint256 that
        // value lives in the lower 16 bytes (bytes[16..32]).
        let mut expected_lo = [0u8; 32];
        for b in expected_lo.iter_mut().skip(16) {
            *b = 0xBB;
        }
        assert_eq!(lo, Fr::from_be_bytes_mod_order(&expected_lo));

        // hi encodes the 128-bit value 0xAAAA...AA — lower 16 bytes.
        let mut expected_hi = [0u8; 32];
        for b in expected_hi.iter_mut().skip(16) {
            *b = 0xAA;
        }
        assert_eq!(hi, Fr::from_be_bytes_mod_order(&expected_hi));
    }
}
