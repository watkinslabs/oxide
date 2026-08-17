//! What a device advertises about inline encryption, and its keyslots.
//!
//! A profile is two things joined. The first is a CLAIM — which modes, at
//! which data unit sizes, with data unit numbers up to which width, and which
//! kinds of key. Every claim is checked before a key is used and again before
//! a request carrying it is submitted, because a request handed to a device
//! that cannot serve its context is a request the device will write in the
//! clear or refuse, and only one of those is detectable.
//!
//! The second is KEYSLOT management, which exists because real controllers
//! hold only a few keys at once. A slot is programmed with a key, referenced
//! while a request using that key is in flight, and returned to a
//! least-recently-used idle list afterwards; a key already in a slot is found
//! there rather than reprogrammed. A device with no slots — a layered device,
//! or a controller that takes the key with each request — says so with a slot
//! count of zero and never sees a program call.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{LockClass, Spinlock};

use crate::crypto::key::{Config, Key, KeyTypes, SW_SECRET_SIZE};
use crate::crypto::mode::{Mode, MODE_SLOTS};
use crate::types::{BlockError, KResult};

/// Keyslot bookkeeping and the driver calls it serialises.
///
/// A leaf: it is taken on the submission path, held across one driver call,
/// and takes no other tracked lock. Ranked above `Devices` so a driver that
/// already holds its own device lock may program a key underneath it.
pub struct BlkCrypto;
impl LockClass for BlkCrypto {
    fn rank() -> u16 { 137 }
    fn name() -> &'static str { "BlkCrypto" }
}

/// What a driver must provide to control its inline encryption hardware.
///
/// Every default refuses rather than succeeds. A profile that advertises
/// hardware-wrapped keys but never implements the derivation would otherwise
/// return a secret it did not derive, and a filesystem would key itself with
/// whatever was in the buffer.
pub trait LlOps: Send + Sync {
    /// Put `key` in `slot`, replacing whatever was there. Only called on a
    /// device that has slots, and only while the slot holds no in-flight
    /// request. # C: one hardware operation
    fn keyslot_program(&self, key: &Key, slot: usize) -> KResult<()> {
        let _ = (key, slot);
        Err(BlockError::Eopnotsupp)
    }

    /// Take `key` out of `slot`, or — on a device with no slots — out of
    /// whatever lies beneath it, in which case there is no slot to name.
    ///
    /// Succeeding by default is correct only because a device with neither
    /// slots nor an underlying device has nowhere the key could still be.
    /// # C: one hardware operation
    fn keyslot_evict(&self, key: &Key, slot: Option<usize>) -> KResult<()> {
        let _ = (key, slot);
        Ok(())
    }

    /// Derive the software secret from an ephemerally-wrapped key.
    /// # C: one hardware operation
    fn derive_sw_secret(&self, eph_key: &[u8]) -> KResult<[u8; SW_SECRET_SIZE]> {
        let _ = eph_key;
        Err(BlockError::Eopnotsupp)
    }

    /// Wrap raw key material into a long-term key. # C: one hardware operation
    fn import_key(&self, raw_key: &[u8]) -> KResult<Vec<u8>> {
        let _ = raw_key;
        Err(BlockError::Eopnotsupp)
    }

    /// Make a new long-term key inside the controller, so its material never
    /// existed in software. # C: one hardware operation
    fn generate_key(&self) -> KResult<Vec<u8>> { Err(BlockError::Eopnotsupp) }

    /// Convert a long-term key to the ephemeral form I/O uses.
    /// # C: one hardware operation
    fn prepare_key(&self, lt_key: &[u8]) -> KResult<Vec<u8>> {
        let _ = lt_key;
        Err(BlockError::Eopnotsupp)
    }
}

struct Slot {
    key: Option<Arc<Key>>,
    refs: u32,
}

struct SlotTable {
    slots: Vec<Slot>,
    /// Idle slot indexes, least recently used first.
    idle: VecDeque<usize>,
}

/// A device's inline encryption capabilities and keyslots.
pub struct Profile {
    ops: Arc<dyn LlOps>,
    /// Widest data unit number, in bytes, this device can be given.
    max_dun_bytes_supported: u32,
    key_types_supported: KeyTypes,
    /// Per mode, the data unit sizes supported, as the set of powers of two:
    /// bit `i` set means a unit of `1 << i` bytes. Indexed by the mode, with
    /// the zero slot permanently empty.
    modes_supported: [u32; MODE_SLOTS],
    num_slots: usize,
    table: Spinlock<SlotTable, BlkCrypto>,
}

/// A held keyslot. The reference is released when this is dropped; a request
/// must hold one for as long as the device may still be reading the key.
pub struct SlotRef<'a> {
    profile: &'a Profile,
    index: usize,
}

impl SlotRef<'_> {
    /// Which slot the key is in — what a driver names it by. # C: O(1)
    pub fn index(&self) -> usize { self.index }
}

impl Drop for SlotRef<'_> {
    /// # C: O(1)
    fn drop(&mut self) {
        let mut t = self.profile.table.lock();
        let s = &mut t.slots[self.index];
        s.refs = s.refs.saturating_sub(1);
        if s.refs == 0 { t.idle.push_back(self.index); }
    }
}

impl Profile {
    /// A profile advertising nothing, with `num_slots` keyslots.
    ///
    /// Capabilities are added afterwards, so a driver that forgets to add any
    /// advertises none — which refuses every key rather than accepting one it
    /// cannot serve.
    /// # C: O(num_slots)
    pub fn new(ops: Arc<dyn LlOps>, num_slots: usize) -> Profile {
        let mut slots = Vec::with_capacity(num_slots);
        let mut idle = VecDeque::with_capacity(num_slots);
        for i in 0..num_slots {
            slots.push(Slot { key: None, refs: 0 });
            idle.push_back(i);
        }
        Profile {
            ops, max_dun_bytes_supported: 0, key_types_supported: KeyTypes::empty(),
            modes_supported: [0; MODE_SLOTS], num_slots,
            table: Spinlock::new(SlotTable { slots, idle }),
        }
    }

    /// Advertise `mode` at every data unit size in `sizes`, a bit per power of
    /// two. # C: O(1)
    pub fn with_mode(mut self, mode: Mode, sizes: u32) -> Profile {
        self.modes_supported[mode.index()] |= sizes;
        self
    }

    /// Advertise `mode` at exactly the data unit sizes between `min` and `max`
    /// bytes inclusive, both powers of two. # C: O(1)
    pub fn with_mode_range(self, mode: Mode, min: u32, max: u32) -> KResult<Profile> {
        if !min.is_power_of_two() || !max.is_power_of_two() || min > max {
            return Err(BlockError::Einval);
        }
        let mut bits = 0u32;
        let mut s = min;
        loop {
            bits |= s;
            if s == max { break; }
            s <<= 1;
        }
        Ok(self.with_mode(mode, bits))
    }

    /// Advertise the widest data unit number this device accepts. # C: O(1)
    pub fn with_max_dun_bytes(mut self, bytes: u32) -> Profile {
        self.max_dun_bytes_supported = bytes;
        self
    }

    /// Advertise which kinds of key this device takes. # C: O(1)
    pub fn with_key_types(mut self, types: KeyTypes) -> Profile {
        self.key_types_supported = types;
        self
    }

    /// Keyslots this device has; zero means it has no such concept. # C: O(1)
    pub fn num_slots(&self) -> usize { self.num_slots }

    /// The kinds of key advertised. # C: O(1)
    pub fn key_types(&self) -> KeyTypes { self.key_types_supported }

    /// Whether this device can serve `cfg` ITSELF — not whether the request
    /// can be served at all, which is a question about the fallback too.
    /// # C: O(1)
    pub fn supports(&self, cfg: &Config) -> bool {
        // The advertised set is a set of POWERS OF TWO, and the size asked
        // for is one; testing the bit is therefore the whole membership test.
        self.modes_supported[cfg.mode.index()] & cfg.data_unit_size != 0
            && self.max_dun_bytes_supported >= cfg.dun_bytes
            && self.key_types_supported.contains(cfg.key_type.bit())
    }

    /// Get a slot holding `key`, programming one if the key is not already in
    /// a slot.
    ///
    /// `Ok(None)` means no slot was needed, which is the answer for a device
    /// with no slots — not a failure and not a refusal.
    ///
    /// When every slot is busy this waits. Waiting cannot deadlock here
    /// because a slot is only ever held across one submission, and a submitter
    /// holding a slot never asks for a second one.
    /// # C: O(num_slots) per attempt
    pub fn get_keyslot(&self, key: &Arc<Key>) -> KResult<Option<SlotRef<'_>>> {
        if self.num_slots == 0 { return Ok(None); }
        loop {
            {
                let mut t = self.table.lock();
                if let Some(i) = find(&t, key) {
                    if t.slots[i].refs == 0 { remove_idle(&mut t, i); }
                    t.slots[i].refs += 1;
                    return Ok(Some(SlotRef { profile: self, index: i }));
                }
                if let Some(i) = t.idle.pop_front() {
                    // Programmed under the lock, which is the serialization
                    // the driver interface promises: no two programs, and no
                    // program racing an evict, reach the hardware at once.
                    self.ops.keyslot_program(key, i)?;
                    t.slots[i] = Slot { key: Some(Arc::clone(key)), refs: 1 };
                    return Ok(Some(SlotRef { profile: self, index: i }));
                }
            }
            core::hint::spin_loop();
        }
    }

    /// Take `key` out of whatever slot holds it, and out of the hardware.
    ///
    /// A key that is in no slot is not an error: there are more keys than
    /// slots, and a key not currently doing I/O has no reason to be resident.
    /// # C: O(num_slots)
    pub fn evict_key(&self, key: &Arc<Key>) -> KResult<()> {
        let mut t = self.table.lock();
        if self.num_slots == 0 { return self.ops.keyslot_evict(key, None); }
        let Some(i) = find(&t, key) else { return Ok(()) };
        // A key still referenced by I/O cannot be evicted; reporting success
        // would tell the caller it may free key material the device is using.
        if t.slots[i].refs != 0 { return Err(BlockError::Ebusy); }
        let r = self.ops.keyslot_evict(key, Some(i));
        // Unlinked even when the hardware refused, because the caller frees
        // the key either way and a slot pointing at freed material is worse
        // than a slot the hardware still holds.
        t.slots[i].key = None;
        r
    }

    /// Re-program every slot that is supposed to hold a key — for hardware
    /// that loses its keys across a reset. # C: O(num_slots)
    pub fn reprogram_all(&self) -> KResult<()> {
        let t = self.table.lock();
        for i in 0..self.num_slots {
            if let Some(k) = t.slots[i].key.as_ref() { self.ops.keyslot_program(k, i)?; }
        }
        Ok(())
    }

    /// Derive the software secret from an ephemerally-wrapped key. # C: one op
    pub fn derive_sw_secret(&self, eph_key: &[u8]) -> KResult<[u8; SW_SECRET_SIZE]> {
        self.hw_wrapped_gate()?;
        self.ops.derive_sw_secret(eph_key)
    }

    /// Wrap raw key material into a long-term key. # C: one op
    pub fn import_key(&self, raw_key: &[u8]) -> KResult<Vec<u8>> {
        self.hw_wrapped_gate()?;
        self.ops.import_key(raw_key)
    }

    /// Make a long-term key whose material never existed in software.
    /// # C: one op
    pub fn generate_key(&self) -> KResult<Vec<u8>> {
        self.hw_wrapped_gate()?;
        self.ops.generate_key()
    }

    /// Convert a long-term key to the ephemeral form I/O uses. # C: one op
    pub fn prepare_key(&self, lt_key: &[u8]) -> KResult<Vec<u8>> {
        self.hw_wrapped_gate()?;
        self.ops.prepare_key(lt_key)
    }

    /// Every wrapped-key operation is refused outright on a device that does
    /// not advertise wrapped keys, before the driver is asked. # C: O(1)
    fn hw_wrapped_gate(&self) -> KResult<()> {
        if !self.key_types_supported.contains(KeyTypes::HW_WRAPPED) {
            return Err(BlockError::Eopnotsupp);
        }
        Ok(())
    }

    /// Clear every capability this profile has that `child` lacks, which is
    /// what a layered device may honestly advertise. A missing child leaves
    /// nothing. # C: O(MODE_SLOTS)
    pub fn intersect(&mut self, child: Option<&Profile>) {
        match child {
            Some(c) => {
                self.max_dun_bytes_supported =
                    self.max_dun_bytes_supported.min(c.max_dun_bytes_supported);
                for i in 0..MODE_SLOTS { self.modes_supported[i] &= c.modes_supported[i]; }
                self.key_types_supported &= c.key_types_supported;
            }
            None => {
                self.max_dun_bytes_supported = 0;
                self.modes_supported = [0; MODE_SLOTS];
                self.key_types_supported = KeyTypes::empty();
            }
        }
    }

    /// Whether this profile advertises everything `reference` does. # C: O(1)
    pub fn has_capabilities(&self, reference: &Profile) -> bool {
        for i in 0..MODE_SLOTS {
            if reference.modes_supported[i] & !self.modes_supported[i] != 0 { return false; }
        }
        reference.max_dun_bytes_supported <= self.max_dun_bytes_supported
            && (reference.key_types_supported & !self.key_types_supported).is_empty()
    }
}

/// The slot holding `key`, by the key's identity rather than its bytes.
/// # C: O(num_slots)
fn find(t: &SlotTable, key: &Arc<Key>) -> Option<usize> {
    t.slots.iter().position(|s| s.key.as_ref().is_some_and(|k| Arc::ptr_eq(k, key)))
}

/// # C: O(num_slots)
fn remove_idle(t: &mut SlotTable, i: usize) {
    if let Some(p) = t.idle.iter().position(|&x| x == i) { t.idle.remove(p); }
}
