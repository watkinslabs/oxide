//! An inline encryption key: its bytes, and the configuration that says how
//! they may be used.
//!
//! Two kinds exist and the difference is where the key can be read.
//!
//! - A RAW key is key material. It sits in kernel memory in the clear, any
//!   software that can read that memory can use it, and the software fallback
//!   can therefore serve it.
//! - A HARDWARE-WRAPPED key is not key material. It is a blob only the
//!   storage controller can unwrap, in one of two forms: a LONG-TERM one that
//!   may be stored and survives a reboot, and an EPHEMERAL one, valid only
//!   until the machine next boots, which is the form I/O actually uses.
//!   Nothing in software can encrypt with it, so no fallback can serve it and
//!   a device that cannot take one must refuse rather than substitute.
//!
//! That asymmetry is the reason the key type is part of the configuration a
//! device is asked about, rather than a detail of the bytes.

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::mode::Mode;
use crate::types::{BlockError, KResult};

/// Longest raw key any mode takes — the tweakable 256-bit mode's two keys.
pub const MAX_RAW_KEY_SIZE: usize = 64;

/// Longest hardware-wrapped key this layer will hold.
///
/// Unlike a raw key there is no width the format fixes: how large a wrapped
/// blob is depends on how the controller wraps it. This bound is the one
/// software imposes so a key has somewhere to live.
pub const MAX_HW_WRAPPED_KEY_SIZE: usize = 128;

/// Bytes of the secret a controller derives from a hardware-wrapped key for
/// software to use.
///
/// The secret is deliberately NOT the inline encryption key: it comes out of a
/// different derivation context, so software holding it learns nothing about
/// what the device encrypts with. A filesystem uses it for everything that is
/// not file contents — subkeys, the key's public name — and for nothing else.
pub const SW_SECRET_SIZE: usize = 32;

/// Which kind of key.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum KeyType {
    Raw,
    HwWrapped,
}

bitflags::bitflags! {
    /// The kinds a device will accept. A device may take both, and a device
    /// that takes neither advertises no inline encryption at all.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct KeyTypes: u32 {
        const RAW        = 1 << 0;
        const HW_WRAPPED = 1 << 1;
    }
}

impl KeyType {
    /// This kind as the single bit a device's advertisement is tested against.
    /// # C: O(1)
    pub const fn bit(self) -> KeyTypes {
        match self { KeyType::Raw => KeyTypes::RAW, KeyType::HwWrapped => KeyTypes::HW_WRAPPED }
    }
}

/// What a key is for: everything a device must agree to before the key may be
/// used on it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Config {
    pub mode: Mode,
    /// Bytes of one plaintext and one ciphertext unit. Always a power of two;
    /// typically a filesystem block or a device sector.
    pub data_unit_size: u32,
    /// Bytes of data unit number this key will ever use. A device that
    /// addresses fewer bytes than a key needs cannot serve it, so this is a
    /// property of the KEY rather than of any one request.
    pub dun_bytes: u32,
    pub key_type: KeyType,
}

/// A prepared key. Immutable once made; many requests reference one at a time.
///
/// Its identity is its ADDRESS, not its bytes: two requests share a key when
/// they point at the same one, and the merge rule compares them that way. A
/// value comparison would let two independently prepared keys with identical
/// bytes merge, which is harmless here but hides the case where a caller
/// prepared a second key by mistake.
pub struct Key {
    cfg: Config,
    /// log2 of the data unit size, so the units in a byte count are a shift.
    du_bits: u32,
    bytes: Vec<u8>,
}

impl Key {
    /// Prepare `bytes` for use under `cfg`, or say why they cannot be.
    ///
    /// A raw key must be EXACTLY the mode's key size — the construction
    /// consumes that many bytes and a shorter one has no material for the
    /// tail. A wrapped key has no fixed size, so the only floor is the mode's
    /// security strength: a controller cannot unwrap more entropy than went in.
    /// # C: O(len(bytes))
    pub fn new(bytes: &[u8], key_type: KeyType, mode: Mode, dun_bytes: u32,
        data_unit_size: u32) -> KResult<Key> {
        let p = mode.params();
        match key_type {
            KeyType::Raw => if bytes.len() != p.key_size { return Err(BlockError::Einval); },
            KeyType::HwWrapped =>
                if bytes.len() < p.security_strength || bytes.len() > MAX_HW_WRAPPED_KEY_SIZE {
                    return Err(BlockError::Einval);
                },
        }
        // A key that never names a data unit encrypts every unit at the same
        // keystream position; a key naming more bytes than the IV holds names
        // units the construction cannot distinguish.
        if dun_bytes == 0 || dun_bytes as usize > p.iv_size { return Err(BlockError::Einval); }
        if !data_unit_size.is_power_of_two() { return Err(BlockError::Einval); }
        Ok(Key {
            cfg: Config { mode, data_unit_size, dun_bytes, key_type },
            du_bits: data_unit_size.trailing_zeros(),
            bytes: Vec::from(bytes),
        })
    }

    /// What this key is for. # C: O(1)
    pub fn config(&self) -> &Config { &self.cfg }

    /// The key's bytes — raw material, or a wrapped blob, per its type.
    /// # C: O(1)
    pub fn bytes(&self) -> &[u8] { &self.bytes }

    /// Bytes of one data unit. # C: O(1)
    pub fn data_unit_size(&self) -> u32 { self.cfg.data_unit_size }

    /// How many data units `bytes` covers. # C: O(1)
    pub fn units(&self, bytes: u64) -> u64 { bytes >> self.du_bits }

    /// Whether `bytes` is a whole number of data units. # C: O(1)
    pub fn unit_aligned(&self, bytes: u64) -> bool {
        bytes & (u64::from(self.cfg.data_unit_size) - 1) == 0
    }
}
