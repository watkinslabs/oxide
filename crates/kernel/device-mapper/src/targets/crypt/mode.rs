//! The chaining modes a `crypt` target encrypts a sector with.
//!
//! Each transforms exactly one encryption unit in place, and each is its own
//! inverse pair. A mode that encrypts correctly but decrypts to something else
//! destroys a volume silently, so both directions are tested as a round trip
//! and against the property that changing one input byte changes the output.

extern crate alloc;

use aes::block::{AesKey, BLOCK_LEN};

use super::iv::{decrypt_block, encrypt_block};
use super::spec::ChainMode;

/// Keys a mode holds. The tweakable mode takes two: the bulk key and the
/// tweak key, cut from one key string in that order.
pub enum ModeKeys {
    /// One key, for chaining and codebook modes.
    Single(AesKey),
    /// Bulk key and tweak key, in that order.
    Pair(AesKey, AesKey),
}

/// Split the key string the table line carried into what the mode needs.
///
/// The tweakable mode's key string is two keys concatenated, so a 512-bit
/// string is two 256-bit keys rather than one 512-bit one. Splitting it the
/// other way produces a device that is self-consistent and unreadable
/// anywhere else. # C: O(key.len())
pub fn keys_for(chain: ChainMode, key: &[u8]) -> Option<ModeKeys> {
    match chain {
        ChainMode::Xts => {
            if key.len() % 2 != 0 { return None; }
            let half = key.len() / 2;
            Some(ModeKeys::Pair(AesKey::new(&key[..half])?, AesKey::new(&key[half..])?))
        }
        _ => Some(ModeKeys::Single(AesKey::new(key)?)),
    }
}

/// The key the IV generator derives its salt from — the bulk half only.
/// # C: O(1)
pub fn iv_key_material(chain: ChainMode, key: &[u8]) -> &[u8] {
    match chain {
        ChainMode::Xts if key.len() % 2 == 0 => &key[..key.len() / 2],
        _ => key,
    }
}

/// Encrypt one unit in place. `unit` must be a whole number of cipher blocks.
/// # C: O(unit.len())
pub fn encrypt(chain: ChainMode, keys: &ModeKeys, iv: &[u8; BLOCK_LEN], unit: &mut [u8]) {
    match (chain, keys) {
        (ChainMode::Ecb, ModeKeys::Single(k)) => for b in unit.chunks_exact_mut(BLOCK_LEN) {
            let mut blk = to_block(b); encrypt_block(k, &mut blk); b.copy_from_slice(&blk);
        },
        (ChainMode::Cbc, ModeKeys::Single(k)) => {
            let mut prev = *iv;
            for b in unit.chunks_exact_mut(BLOCK_LEN) {
                let mut blk = to_block(b);
                for i in 0..BLOCK_LEN { blk[i] ^= prev[i]; }
                encrypt_block(k, &mut blk);
                b.copy_from_slice(&blk);
                prev = blk;
            }
        }
        (ChainMode::Xts, ModeKeys::Pair(bulk, tweak)) => {
            let mut t = *iv;
            encrypt_block(tweak, &mut t);
            for b in unit.chunks_exact_mut(BLOCK_LEN) {
                let mut blk = to_block(b);
                for i in 0..BLOCK_LEN { blk[i] ^= t[i]; }
                encrypt_block(bulk, &mut blk);
                for i in 0..BLOCK_LEN { blk[i] ^= t[i]; }
                b.copy_from_slice(&blk);
                t = shift_tweak(t);
            }
        }
        // A key set that does not match its mode cannot be built by
        // `keys_for`, so this arm is unreachable; leaving the data untouched
        // is the only choice that cannot write wrong ciphertext.
        _ => {}
    }
}

/// Decrypt one unit in place. # C: O(unit.len())
pub fn decrypt(chain: ChainMode, keys: &ModeKeys, iv: &[u8; BLOCK_LEN], unit: &mut [u8]) {
    match (chain, keys) {
        (ChainMode::Ecb, ModeKeys::Single(k)) => for b in unit.chunks_exact_mut(BLOCK_LEN) {
            let mut blk = to_block(b); decrypt_block(k, &mut blk); b.copy_from_slice(&blk);
        },
        (ChainMode::Cbc, ModeKeys::Single(k)) => {
            let mut prev = *iv;
            for b in unit.chunks_exact_mut(BLOCK_LEN) {
                let cipher = to_block(b);
                let mut blk = cipher;
                decrypt_block(k, &mut blk);
                for i in 0..BLOCK_LEN { blk[i] ^= prev[i]; }
                b.copy_from_slice(&blk);
                prev = cipher;
            }
        }
        (ChainMode::Xts, ModeKeys::Pair(bulk, tweak)) => {
            let mut t = *iv;
            encrypt_block(tweak, &mut t);
            for b in unit.chunks_exact_mut(BLOCK_LEN) {
                let mut blk = to_block(b);
                for i in 0..BLOCK_LEN { blk[i] ^= t[i]; }
                decrypt_block(bulk, &mut blk);
                for i in 0..BLOCK_LEN { blk[i] ^= t[i]; }
                b.copy_from_slice(&blk);
                t = shift_tweak(t);
            }
        }
        _ => {}
    }
}

fn to_block(b: &[u8]) -> [u8; BLOCK_LEN] {
    let mut out = [0u8; BLOCK_LEN];
    out.copy_from_slice(b);
    out
}

/// Advance the tweak by multiplying it by the field generator: a left shift of
/// the whole 128-bit little-endian value, reducing by the polynomial when the
/// top bit carries out. # C: O(1)
fn shift_tweak(t: [u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    const REDUCE: u8 = 0x87;
    let mut out = [0u8; BLOCK_LEN];
    let mut carry = 0u8;
    for i in 0..BLOCK_LEN {
        let next = t[i] >> 7;
        out[i] = (t[i] << 1) | carry;
        carry = next;
    }
    if carry != 0 { out[0] ^= REDUCE; }
    out
}
