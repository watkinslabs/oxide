//! The software construction each inline mode names.
//!
//! These exist so the fallback can do in software exactly what a controller
//! would have done in line with the transfer. "Exactly" is the requirement,
//! not a goal: a volume written through the fallback and later read by
//! hardware — or the reverse, which is what happens when a disk moves between
//! machines — must produce the same bytes. Each construction decrypts its own
//! output perfectly, so a divergence here is invisible until the other
//! implementation reads the volume and finds noise.
//!
//! The IV is presented at its widest and a narrower mode reads only its low
//! bytes, which is the same presentation the data unit number produces.

extern crate alloc;

use aes::block::AesKey;
use aes::cbc;
use aes::xts::Xts;
use sm4::mode::Sm4Xts;
use adiantum::Adiantum;

use crate::crypto::dun::MAX_IV_SIZE;
use crate::crypto::mode::Mode;
use crate::types::{BlockError, KResult};

/// A prepared construction.
pub enum Cipher {
    Xts(Xts),
    /// Chaining whose IV is enciphered under a key derived by hashing the
    /// data key, so a bare data unit number is not a predictable IV.
    CbcEssiv { data: AesKey, essiv: aes::Aes256 },
    Sm4Xts(Sm4Xts),
    Adiantum(Adiantum),
}

/// The 16-byte IV the narrow-block constructions take: the low bytes of the
/// wide one. # C: O(1)
fn narrow(iv: &[u8; MAX_IV_SIZE]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&iv[..16]);
    out
}

impl Cipher {
    /// Prepare the construction `mode` names from `key`, which must be
    /// exactly the mode's key size. # C: O(1)
    pub fn prepare(mode: Mode, key: &[u8]) -> KResult<Cipher> {
        if key.len() != mode.params().key_size { return Err(BlockError::Einval); }
        match mode {
            Mode::Aes256Xts => Xts::new(key).map(Cipher::Xts).map_err(|_| BlockError::Einval),
            Mode::Aes128CbcEssiv => {
                let salt = crypt::sha256::sha256(key);
                let data = AesKey::new(key).ok_or(BlockError::Einval)?;
                Ok(Cipher::CbcEssiv { data, essiv: aes::Aes256::new(&salt) })
            }
            Mode::Adiantum =>
                Adiantum::new(key).map(Cipher::Adiantum).map_err(|_| BlockError::Einval),
            Mode::Sm4Xts =>
                Sm4Xts::new(key).map(Cipher::Sm4Xts).map_err(|_| BlockError::Einval),
        }
    }

    /// Encrypt one data unit in place under `iv`. # C: O(len(buf))
    pub fn encrypt(&self, iv: &[u8; MAX_IV_SIZE], buf: &mut [u8]) -> KResult<()> {
        match self {
            Cipher::Xts(x) => x.encrypt(&narrow(iv), buf).map_err(|_| BlockError::Einval),
            Cipher::CbcEssiv { data, essiv } => {
                let mut v = narrow(iv);
                essiv.encrypt_block(&mut v);
                cbc::encrypt(data, &mut v, buf).map_err(|_| BlockError::Einval)
            }
            Cipher::Sm4Xts(x) => x.encrypt(&narrow(iv), buf).map_err(|_| BlockError::Einval),
            Cipher::Adiantum(a) => a.encrypt(iv, buf).map_err(|_| BlockError::Einval),
        }
    }

    /// Decrypt one data unit in place under `iv`. # C: O(len(buf))
    pub fn decrypt(&self, iv: &[u8; MAX_IV_SIZE], buf: &mut [u8]) -> KResult<()> {
        match self {
            Cipher::Xts(x) => x.decrypt(&narrow(iv), buf).map_err(|_| BlockError::Einval),
            Cipher::CbcEssiv { data, essiv } => {
                let mut v = narrow(iv);
                essiv.encrypt_block(&mut v);
                cbc::decrypt(data, &mut v, buf).map_err(|_| BlockError::Einval)
            }
            Cipher::Sm4Xts(x) => x.decrypt(&narrow(iv), buf).map_err(|_| BlockError::Einval),
            Cipher::Adiantum(a) => a.decrypt(iv, buf).map_err(|_| BlockError::Einval),
        }
    }
}
