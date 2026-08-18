//! Producing the initialisation vector for a sector.
//!
//! The IV is what makes two sectors holding the same plaintext encrypt
//! differently. Every mode here is a fixed function of the sector number, so
//! the whole set is testable against known values without a device.

extern crate alloc;
use alloc::vec::Vec;

use aes::block::{AesKey, BLOCK_LEN};
use crypt::{Sha256, Sha512};

use super::spec::IvMode;

/// Bytes of initialisation vector every mode here produces — one cipher block.
pub const IV_LEN: usize = BLOCK_LEN;

/// The key material an IV mode needs beyond the sector number.
pub enum IvKey {
    /// Modes that need nothing.
    None,
    /// The sector number encrypted under a key derived by hashing the bulk key.
    Essiv(AesKey),
    /// The sector's byte offset encrypted under the bulk key itself.
    Eboiv(AesKey),
    /// Shift derived from the cipher's block size.
    Benbi(u32),
}

/// Build the extra key material `mode` needs from the bulk key.
///
/// The salt for the derived-key mode is the digest of the bulk key, so the IV
/// is unpredictable to anyone who does not hold it — the property that mode
/// exists for. # C: O(key.len())
pub fn prepare(mode: &IvMode, key: &[u8], sector_size: u32) -> Option<IvKey> {
    Some(match mode {
        IvMode::Plain | IvMode::Plain64 | IvMode::Plain64Be | IvMode::Null => IvKey::None,
        IvMode::Eboiv => IvKey::Eboiv(AesKey::new(key)?),
        IvMode::Benbi => {
            // The shift converts a 512-byte sector index into the cipher's own
            // block index, so a cipher with a block smaller than a sector gets
            // a distinct IV per block rather than per sector.
            let log_bs = (BLOCK_LEN as u32).trailing_zeros();
            IvKey::Benbi(crate::uapi::SECTOR_SHIFT.saturating_sub(log_bs) + sector_size.trailing_zeros()
                         - crate::uapi::SECTOR_SHIFT)
        }
        IvMode::Essiv(hash) => {
            let salt: Vec<u8> = match hash.as_str() {
                "sha256" => { let mut d = Sha256::new(); d.update(key); d.finish().to_vec() }
                "sha512" => { let mut d = Sha512::new(); d.update(key); d.finish()[..32].to_vec() }
                _ => return None,
            };
            IvKey::Essiv(AesKey::new(&salt)?)
        }
    })
}

/// Produce the IV for `sector`, in whatever unit the mode counts in.
/// # C: O(1)
pub fn generate(mode: &IvMode, key: &IvKey, sector: u64, sector_size: u32) -> [u8; IV_LEN] {
    let mut iv = [0u8; IV_LEN];
    match mode {
        IvMode::Null => {}
        IvMode::Plain => iv[..4].copy_from_slice(&(sector as u32).to_le_bytes()),
        IvMode::Plain64 => iv[..8].copy_from_slice(&sector.to_le_bytes()),
        // Big endian in the LAST eight bytes, not the first: the two plain64
        // forms differ in position as well as in byte order.
        IvMode::Plain64Be => iv[IV_LEN - 8..].copy_from_slice(&sector.to_be_bytes()),
        IvMode::Benbi => {
            let shift = if let IvKey::Benbi(s) = key { *s } else { 0 };
            let val = (sector << shift) + 1;
            iv[IV_LEN - 8..].copy_from_slice(&val.to_be_bytes());
        }
        IvMode::Essiv(_) => {
            iv[..8].copy_from_slice(&sector.to_le_bytes());
            if let IvKey::Essiv(k) = key { encrypt_block(k, &mut iv); }
        }
        IvMode::Eboiv => {
            let offset = sector.wrapping_mul(sector_size as u64);
            iv[..8].copy_from_slice(&offset.to_le_bytes());
            if let IvKey::Eboiv(k) = key { encrypt_block(k, &mut iv); }
        }
    }
    iv
}

/// Encrypt one block under either key width. # C: O(1)
pub fn encrypt_block(k: &AesKey, b: &mut [u8; BLOCK_LEN]) {
    match k {
        AesKey::K128(c) => c.encrypt_block(b),
        AesKey::K256(c) => c.encrypt_block(b),
    }
}

/// Decrypt one block under either key width. # C: O(1)
pub fn decrypt_block(k: &AesKey, b: &mut [u8; BLOCK_LEN]) {
    match k {
        AesKey::K128(c) => c.decrypt_block(b),
        AesKey::K256(c) => c.decrypt_block(b),
    }
}
