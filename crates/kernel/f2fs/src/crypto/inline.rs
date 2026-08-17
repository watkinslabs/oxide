//! Choosing the block layer to do a file's contents encryption instead of
//! doing it here.
//!
//! Nothing about the CIPHERTEXT changes. The same construction runs over the
//! same data units under the same key at the same data unit numbers; what
//! changes is who runs it, and therefore whether a storage controller can do
//! it in line with the transfer and save the filesystem a pass over every
//! block. A volume written one way reads the other way, which is the property
//! that makes the choice safe to make per mount.
//!
//! It is a choice with four gates, and all four are refusals rather than
//! adjustments:
//!
//! - Only FILE CONTENTS. Filenames are encrypted whole as one message under
//!   constructions no controller implements, so a directory always does its
//!   own crypto whatever the mount asked for.
//! - Only a mode inline encryption defines. The filename modes and the wide
//!   block mode have no counterpart, so a policy naming one keeps the
//!   filesystem's own path.
//! - Only when the mount ASKED. Inline encryption changes where a key lives
//!   and which failures are possible, so it is never turned on by inference.
//! - Only when the configuration can be served — by the device, or by the
//!   software fallback, which is why a raw key can always be served and a
//!   hardware-wrapped one cannot.
//!
//! The last gate is the one that matters most and it is not a formality. If it
//! passed something nothing could serve, the mount would either write file
//! contents in the clear or fail every write to an encrypted file.

extern crate alloc;
use alloc::sync::Arc;

use block::crypto::{Config, Dun, Key, KeyType, Mode as BlkMode, Profile};

use super::mode::Mode;
use super::policy::{FsFacts, InodeFacts, Policy};
use super::uapi::*;
use super::FscryptError;

/// What is available to serve an inline encryption configuration.
pub struct Inline<'a> {
    /// Whether the mount was given `inlinecrypt`.
    pub enabled: bool,
    /// What the device holding the file's blocks can do itself, if anything.
    pub profile: Option<&'a Profile>,
}

impl Inline<'_> {
    /// The mount did not ask. # C: O(1)
    pub const OFF: Inline<'static> = Inline { enabled: false, profile: None };

    /// Whether `cfg` can be served here at all.
    ///
    /// A raw key always can: the software fallback exists precisely so that
    /// asking for inline encryption never turns into writing plaintext. A
    /// hardware-wrapped key is a blob software cannot unwrap, so it can only
    /// be served by a controller that says it takes one.
    /// # C: O(1)
    pub fn supports(&self, cfg: &Config) -> bool {
        cfg.key_type == KeyType::Raw || block::crypto::profile_supports(self.profile, cfg)
    }
}

/// The inline mode a policy's mode number corresponds to, or `None` when it
/// has no counterpart.
///
/// Deliberately partial. The filename modes encrypt a whole padded name as one
/// message and the wide-block contents mode reads every input byte before
/// producing any output byte; neither is something a controller performs over
/// a data unit it addresses, so there is no number to map them to.
/// # C: O(1)
pub fn blk_mode(num: u8) -> Option<BlkMode> {
    match num {
        MODE_AES_256_XTS => Some(BlkMode::Aes256Xts),
        MODE_AES_128_CBC => Some(BlkMode::Aes128CbcEssiv),
        MODE_ADIANTUM => Some(BlkMode::Adiantum),
        MODE_SM4_XTS => Some(BlkMode::Sm4Xts),
        _ => None,
    }
}

/// Bytes of data unit number a policy's IVs will ever occupy.
///
/// This is not the mode's IV width and must not be rounded up to it: it is
/// what the DEVICE is asked to address, and a device advertising fewer bytes
/// than a policy actually uses cannot serve it. Each derivation rule puts a
/// different amount in the IV, so each answers differently.
/// # C: O(1)
pub fn dun_bytes(p: &Policy, fs: &FsFacts, du_bits: u8) -> u32 {
    // The nonce travels beside the index, so the number spans up to the end of
    // the nonce field.
    if p.flags & FLAG_DIRECT_KEY != 0 { return (8 + FILE_NONCE_SIZE) as u32; }
    // The inode number occupies the index's high half, so the whole word is
    // in use.
    if p.flags & FLAG_IV_INO_LBLK_64 != 0 { return 8; }
    // A hashed inode number added to the index, wrapping at 32 bits — the
    // narrow form that exists for controllers which cannot address more.
    if p.flags & FLAG_IV_INO_LBLK_32 != 0 { return 4; }
    // Otherwise the number is only the index, so only as many bytes as the
    // largest index on this volume needs.
    super::support::max_file_dun_bits(fs, du_bits).div_ceil(8)
}

/// The configuration a file would ask a device for. # C: O(1)
pub fn config(p: &Policy, fs: &FsFacts, du_bits: u8, mode: BlkMode, hw_wrapped: bool) -> Config {
    Config {
        mode,
        data_unit_size: 1u32 << du_bits,
        dun_bytes: dun_bytes(p, fs, du_bits),
        key_type: if hw_wrapped { KeyType::HwWrapped } else { KeyType::Raw },
    }
}

/// Whether this inode's contents should be encrypted by the block layer, and
/// under which inline mode.
///
/// `None` means the filesystem does its own crypto, which is always a correct
/// answer and never a silent loss of encryption.
/// # C: O(1)
pub fn select(p: &Policy, inode: &InodeFacts, fs: &FsFacts, du_bits: u8, mode: Mode,
    hw_wrapped: bool, avail: &Inline<'_>) -> Option<BlkMode> {
    if !inode.is_reg { return None; }
    let bm = blk_mode(mode.num)?;
    if !avail.enabled { return None; }
    if !avail.supports(&config(p, fs, du_bits, bm, hw_wrapped)) { return None; }
    Some(bm)
}

/// The key the block layer is given for this file.
///
/// A hardware-wrapped key is handed over AS IT IS: it is not derived from and
/// not derived through, because the only thing that can unwrap it is the
/// controller. A raw key is whatever the policy's derivation produced.
/// # C: O(key size)
pub fn make_key(raw: &[u8], mode: BlkMode, cfg: &Config, avail: &Inline<'_>)
    -> Result<Arc<Key>, FscryptError> {
    let key = Key::new(raw, cfg.key_type, mode, cfg.dun_bytes, cfg.data_unit_size)
        .map(Arc::new)
        .map_err(|_| FscryptError::BadKeySize(raw.len()))?;
    // Preparing the key is what makes the first write to this file a write
    // rather than a discovery. Whatever will serve it — the device or the
    // software fallback — is made ready here, away from the I/O path, and a
    // refusal reaches the caller opening the file instead of the caller
    // writing to it.
    block::crypto::start_using_key_on(avail.profile, &key)
        .map_err(|_| FscryptError::HwWrappedNoInline)?;
    Ok(key)
}

/// The data unit number for a file's data unit `index`, from the IV the
/// policy's derivation rule produces.
///
/// The two representations are the same bytes read two ways: the filesystem's
/// IV is a byte string, and the number is its low limbs read little-endian.
/// Only the limbs the mode's IV actually spans are read, so a wider number
/// than the mode defines can never be handed to a device.
/// # C: O(1)
pub fn dun_for(iv: &[u8; MAX_IV_SIZE], iv_size: usize) -> Dun {
    let mut limbs = [0u64; block::crypto::DUN_LIMBS];
    for (i, limb) in limbs.iter_mut().enumerate().take(iv_size / 8) {
        let mut w = [0u8; 8];
        w.copy_from_slice(&iv[i * 8..i * 8 + 8]);
        *limb = u64::from_le_bytes(w);
    }
    Dun::from_limbs(limbs)
}

/// How many of `nr_blocks` from `lblk` may share one request without the data
/// unit number wrapping inside it.
///
/// Only one derivation rule can wrap at all: the one that adds a hashed inode
/// number to the index and truncates to 32 bits, which exists for controllers
/// that cannot address more. When it wraps mid-request the units after the
/// wrap are encrypted at numbers the units before it already used, and every
/// layer accepts the result.
/// # C: O(1)
pub fn limit_io_blocks(p: &Policy, hashed_ino: u32, lblk: u64, nr_blocks: u64) -> u64 {
    if nr_blocks <= 1 { return nr_blocks; }
    if p.flags & FLAG_IV_INO_LBLK_32 == 0 { return nr_blocks; }
    let dun = u64::from(hashed_ino.wrapping_add(lblk as u32));
    nr_blocks.min((u64::from(u32::MAX) + 1) - dun)
}
