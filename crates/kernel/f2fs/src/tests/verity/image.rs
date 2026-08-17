//! Verity records assembled byte by byte from the on-disk format.

use alloc::vec;
use alloc::vec::Vec;

use crate::verity::uapi::*;

/// The attribute value: a version, a length and a position.
pub fn location(version: u32, size: u32, pos: u64) -> Vec<u8> {
    let mut v = vec![0u8; LOCATION_SIZE];
    v[LOC_VERSION..LOC_VERSION + 4].copy_from_slice(&version.to_le_bytes());
    v[LOC_SIZE..LOC_SIZE + 4].copy_from_slice(&size.to_le_bytes());
    v[LOC_POS..LOC_POS + 8].copy_from_slice(&pos.to_le_bytes());
    v
}

/// A descriptor, written field by field.
pub fn descriptor(alg: u8, log_blocksize: u8, salt_size: u8, data_size: u64) -> Vec<u8> {
    let mut d = vec![0u8; DESCRIPTOR_SIZE];
    d[D_VERSION] = DESCRIPTOR_VERSION;
    d[D_HASH_ALGORITHM] = alg;
    d[D_LOG_BLOCKSIZE] = log_blocksize;
    d[D_SALT_SIZE] = salt_size;
    d[D_DATA_SIZE..D_DATA_SIZE + 8].copy_from_slice(&data_size.to_le_bytes());
    for i in 0..SHA256_DIGEST_SIZE { d[D_ROOT_HASH + i] = 0xa0 + (i as u8 & 0xf); }
    for i in 0..salt_size as usize { d[D_SALT + i] = 0x5a; }
    d
}

/// Append a built-in signature and declare it.
pub fn with_signature(mut d: Vec<u8>, sig: &[u8]) -> Vec<u8> {
    d[D_SIG_SIZE..D_SIG_SIZE + 4].copy_from_slice(&(sig.len() as u32).to_le_bytes());
    d.extend_from_slice(sig);
    d
}
