// Public AES block-cipher types. Key material is expanded once at
// construction; encrypt/decrypt take no allocation and no interior mutability.

use super::cipher::{self, BLOCK, MAX_RK};

/// Bytes per AES block.
pub const BLOCK_LEN: usize = BLOCK;

/// AES-128 key length, bytes.
pub const AES128_KEY_LEN: usize = 16;
/// AES-256 key length, bytes.
pub const AES256_KEY_LEN: usize = 32;

const AES128_ROUNDS: usize = 10;
const AES256_ROUNDS: usize = 14;

const AES128_RK: usize = BLOCK * (AES128_ROUNDS + 1);
const AES256_RK: usize = BLOCK * (AES256_ROUNDS + 1);

/// AES with a 128-bit key.
#[derive(Clone)]
pub struct Aes128 { rk: [u8; AES128_RK] }

impl Aes128 {
    /// Expand a 128-bit key.
    /// # C: O(1) — 44-word key schedule
    pub fn new(key: &[u8; AES128_KEY_LEN]) -> Self {
        let mut rk = [0u8; AES128_RK];
        cipher::expand(key, &mut rk, AES128_ROUNDS);
        Self { rk }
    }

    /// Encrypt one 16-byte block in place.
    /// # C: O(1) — 10 rounds
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) { cipher::encrypt(&self.rk, AES128_ROUNDS, block); }

    /// Decrypt one 16-byte block in place.
    /// # C: O(1) — 10 rounds
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) { cipher::decrypt(&self.rk, AES128_ROUNDS, block); }
}

/// AES with a 256-bit key.
#[derive(Clone)]
pub struct Aes256 { rk: [u8; AES256_RK] }

impl Aes256 {
    /// Expand a 256-bit key.
    /// # C: O(1) — 60-word key schedule
    pub fn new(key: &[u8; AES256_KEY_LEN]) -> Self {
        let mut rk = [0u8; AES256_RK];
        cipher::expand(key, &mut rk, AES256_ROUNDS);
        Self { rk }
    }

    /// Encrypt one 16-byte block in place.
    /// # C: O(1) — 14 rounds
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) { cipher::encrypt(&self.rk, AES256_ROUNDS, block); }

    /// Decrypt one 16-byte block in place.
    /// # C: O(1) — 14 rounds
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) { cipher::decrypt(&self.rk, AES256_ROUNDS, block); }
}

/// A key of either width the link ciphers use, so a mode is generic over both
/// without a trait object.
#[derive(Clone)]
pub enum AesKey { K128(Aes128), K256(Aes256) }

impl AesKey {
    /// Build from a 16- or 32-byte key; any other length yields `None`.
    /// # C: O(1)
    pub fn new(key: &[u8]) -> Option<Self> {
        match key.len() {
            AES128_KEY_LEN => { let mut k = [0u8; AES128_KEY_LEN]; k.copy_from_slice(key); Some(Self::K128(Aes128::new(&k))) }
            AES256_KEY_LEN => { let mut k = [0u8; AES256_KEY_LEN]; k.copy_from_slice(key); Some(Self::K256(Aes256::new(&k))) }
            _ => None,
        }
    }

    /// Encrypt one 16-byte block in place.
    /// # C: O(1)
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        match self { Self::K128(k) => k.encrypt_block(block), Self::K256(k) => k.encrypt_block(block) }
    }

    /// Decrypt one 16-byte block in place.
    /// # C: O(1)
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        match self { Self::K128(k) => k.decrypt_block(block), Self::K256(k) => k.decrypt_block(block) }
    }

    /// Key length in bytes.
    /// # C: O(1)
    pub fn key_len(&self) -> usize {
        match self { Self::K128(_) => AES128_KEY_LEN, Self::K256(_) => AES256_KEY_LEN }
    }
}

const _: () = assert!(AES256_RK == MAX_RK);
