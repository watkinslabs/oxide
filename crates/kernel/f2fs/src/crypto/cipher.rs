//! The ciphers a mode names, prepared once per inode.
//!
//! Five constructions carry file contents and three carry names:
//!
//! - The tweakable narrow-block mode, whose key is TWO cipher keys in one
//!   buffer and whose tweak is the IV. Both block ciphers take it.
//! - Chaining with an IV that is itself enciphered under a key derived by
//!   hashing the file key — so the IV is unpredictable without the key, which
//!   a bare block index is not.
//! - Chaining with ciphertext stealing, which keeps a name's exact length.
//!   Both block ciphers take this one too.
//! - Two wide-block modes, in which every output byte depends on every input
//!   byte of the unit. They take a 32-byte tweak rather than a block-wide IV,
//!   and are the only modes whose tweak has room for a file nonce.
//!
//! Each is a different answer for the same bytes, and each decrypts its own
//! output perfectly, so picking the wrong one is invisible without a second
//! implementation to disagree with.

use aes::block::AesKey;
use aes::cbc;
use aes::hctr2::Hctr2;
use aes::xts::Xts;
use adiantum::Adiantum;
use blockcipher::cipher::BlockCipher;
use sm4::block::Sm4;
use sm4::mode::Sm4Xts;

use super::iv::block_iv;
use super::mode::Mode;
use super::uapi::*;
use super::FscryptError;

/// Bytes a contents request must be a multiple of.
pub const CONTENTS_ALIGNMENT: usize = 16;

/// A prepared cipher.
#[derive(Clone)]
pub enum Cipher {
    /// Tweakable narrow-block over the 128-bit-block Western cipher.
    Xts(Xts),
    /// Chaining with an enciphered IV, for file contents.
    CbcEssiv { data: AesKey, essiv: aes::Aes256 },
    /// Chaining with ciphertext stealing, for names.
    Cts(AesKey),
    /// Tweakable narrow-block over the other block cipher.
    Sm4Xts(Sm4Xts),
    /// Chaining with ciphertext stealing over the other block cipher.
    Sm4Cts(Sm4),
    /// Wide-block over a stream cipher and two hashing passes.
    Adiantum(Adiantum),
    /// Wide-block over counter mode and a polynomial hash.
    Hctr2(Hctr2),
}

impl Cipher {
    /// Prepare the cipher `mode` names from `key`, which must be exactly the
    /// mode's key size. # C: O(1)
    #[inline(never)]
    pub fn prepare(mode: Mode, key: &[u8]) -> Result<Self, FscryptError> {
        let bad = || FscryptError::BadKeySize(key.len());
        if key.len() != mode.key_size { return Err(bad()); }
        match mode.num {
            MODE_AES_256_XTS => Xts::new(key).map(Cipher::Xts).map_err(|_| bad()),
            MODE_AES_128_CBC => {
                // The IV key is the digest of the file key, so a predictable
                // block index becomes an unpredictable IV.
                let salt = crypt::sha256::sha256(key);
                let data = AesKey::new(key).ok_or_else(bad)?;
                Ok(Cipher::CbcEssiv { data, essiv: aes::Aes256::new(&salt) })
            }
            MODE_AES_256_CTS | MODE_AES_128_CTS =>
                AesKey::new(key).map(Cipher::Cts).ok_or_else(bad),
            MODE_SM4_XTS => Sm4Xts::new(key).map(Cipher::Sm4Xts).map_err(|_| bad()),
            MODE_SM4_CTS => Sm4::from_key(key).map(Cipher::Sm4Cts).ok_or_else(bad),
            MODE_ADIANTUM => Adiantum::new(key).map(Cipher::Adiantum).map_err(|_| bad()),
            MODE_AES_256_HCTR2 => Hctr2::new(key).map(Cipher::Hctr2).map_err(|_| bad()),
            other => Err(FscryptError::UnsupportedMode(other)),
        }
    }

    /// Encrypt `buf` in place under `iv`.
    ///
    /// The IV is presented at its widest; a mode narrower than that reads only
    /// the bytes it defines, which are the low ones. # C: O(len(buf))
    pub fn encrypt(&self, iv: &[u8; MAX_IV_SIZE], buf: &mut [u8]) -> Result<(), FscryptError> {
        let n = buf.len();
        let len = move || FscryptError::BadLength(n);
        let b = block_iv(iv);
        match self {
            Cipher::Xts(x) => x.encrypt(&b, buf).map_err(|_| len()),
            Cipher::CbcEssiv { data, essiv } => {
                let mut v = b;
                essiv.encrypt_block(&mut v);
                cbc::encrypt(data, &mut v, buf).map_err(|_| len())
            }
            Cipher::Cts(k) => cbc::cts_encrypt(k, &b, buf).map_err(|_| len()),
            Cipher::Sm4Xts(x) => x.encrypt(&b, buf).map_err(|_| len()),
            Cipher::Sm4Cts(k) => cbc::cts_encrypt(k, &b, buf).map_err(|_| len()),
            Cipher::Adiantum(a) => a.encrypt(iv, buf).map_err(|_| len()),
            Cipher::Hctr2(h) => h.encrypt(iv, buf).map_err(|_| len()),
        }
    }

    /// Decrypt `buf` in place under `iv`. # C: O(len(buf))
    pub fn decrypt(&self, iv: &[u8; MAX_IV_SIZE], buf: &mut [u8]) -> Result<(), FscryptError> {
        let n = buf.len();
        let len = move || FscryptError::BadLength(n);
        let b = block_iv(iv);
        match self {
            Cipher::Xts(x) => x.decrypt(&b, buf).map_err(|_| len()),
            Cipher::CbcEssiv { data, essiv } => {
                let mut v = b;
                essiv.encrypt_block(&mut v);
                cbc::decrypt(data, &mut v, buf).map_err(|_| len())
            }
            Cipher::Cts(k) => cbc::cts_decrypt(k, &b, buf).map_err(|_| len()),
            Cipher::Sm4Xts(x) => x.decrypt(&b, buf).map_err(|_| len()),
            Cipher::Sm4Cts(k) => cbc::cts_decrypt(k, &b, buf).map_err(|_| len()),
            Cipher::Adiantum(a) => a.decrypt(iv, buf).map_err(|_| len()),
            Cipher::Hctr2(h) => h.decrypt(iv, buf).map_err(|_| len()),
        }
    }
}
