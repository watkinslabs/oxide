// What a profile claims, the keyslots behind the claim, and the refusals a
// device that cannot take hardware-wrapped keys must produce.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use sync::Spinlock;
use sync::Inode as InodeClass;

use crate::crypto::key::{Config, Key, KeyType, KeyTypes, SW_SECRET_SIZE};
use crate::crypto::mode::Mode;
use crate::crypto::profile::{LlOps, Profile};
use crate::types::{BlockError, KResult};

use super::raw_key;

/// A controller that records what it was asked to do.
struct Recorder {
    programmed: Spinlock<Vec<(usize, Vec<u8>)>, InodeClass>,
    evicted: Spinlock<Vec<Option<usize>>, InodeClass>,
    /// Whether this controller can unwrap keys at all.
    wrapped: bool,
}

impl LlOps for Recorder {
    fn keyslot_program(&self, key: &Key, slot: usize) -> KResult<()> {
        self.programmed.lock().push((slot, key.bytes().to_vec()));
        Ok(())
    }
    fn keyslot_evict(&self, _key: &Key, slot: Option<usize>) -> KResult<()> {
        self.evicted.lock().push(slot);
        Ok(())
    }
    fn derive_sw_secret(&self, eph_key: &[u8]) -> KResult<[u8; SW_SECRET_SIZE]> {
        if !self.wrapped { return Err(BlockError::Eopnotsupp); }
        // A stand-in for a controller's derivation: distinct from the key, and
        // a function of it, which is all a test can ask of an opaque unwrap.
        let mut out = [0u8; SW_SECRET_SIZE];
        for (i, o) in out.iter_mut().enumerate() { *o = eph_key[i % eph_key.len()] ^ 0x5a; }
        Ok(out)
    }
}

fn rec(wrapped: bool) -> Arc<Recorder> {
    Arc::new(Recorder {
        programmed: Spinlock::new(Vec::new()),
        evicted: Spinlock::new(Vec::new()),
        wrapped,
    })
}

fn profile(ops: Arc<Recorder>, slots: usize, types: KeyTypes) -> Profile {
    Profile::new(ops as Arc<dyn LlOps>, slots)
        .with_mode(Mode::Aes256Xts, 4096)
        .with_max_dun_bytes(8)
        .with_key_types(types)
}

fn cfg(mode: Mode, dus: u32, dun: u32, t: KeyType) -> Config {
    Config { mode, data_unit_size: dus, dun_bytes: dun, key_type: t }
}

#[test]
fn a_claim_is_exact_in_every_axis() {
    let p = profile(rec(false), 4, KeyTypes::RAW);
    assert!(p.supports(&cfg(Mode::Aes256Xts, 4096, 8, KeyType::Raw)));
    // A mode not advertised.
    assert!(!p.supports(&cfg(Mode::Adiantum, 4096, 8, KeyType::Raw)));
    // The right mode at a data unit size that was not advertised.
    assert!(!p.supports(&cfg(Mode::Aes256Xts, 512, 8, KeyType::Raw)));
    // A data unit number wider than the device addresses.
    assert!(!p.supports(&cfg(Mode::Aes256Xts, 4096, 16, KeyType::Raw)));
    // A kind of key it does not take.
    assert!(!p.supports(&cfg(Mode::Aes256Xts, 4096, 8, KeyType::HwWrapped)));
}

#[test]
fn a_size_range_advertises_every_power_of_two_within_it() {
    let p = Profile::new(rec(false) as Arc<dyn LlOps>, 0)
        .with_mode_range(Mode::Aes256Xts, 512, 4096).unwrap()
        .with_max_dun_bytes(8)
        .with_key_types(KeyTypes::RAW);
    for s in [512u32, 1024, 2048, 4096] {
        assert!(p.supports(&cfg(Mode::Aes256Xts, s, 8, KeyType::Raw)), "{s}");
    }
    assert!(!p.supports(&cfg(Mode::Aes256Xts, 256, 8, KeyType::Raw)));
    assert!(!p.supports(&cfg(Mode::Aes256Xts, 8192, 8, KeyType::Raw)));
}

#[test]
fn a_key_already_in_a_slot_is_not_reprogrammed() {
    let ops = rec(false);
    let p = profile(ops.clone(), 4, KeyTypes::RAW);
    let k = raw_key(Mode::Aes256Xts, 1, 4096);
    {
        let s1 = p.get_keyslot(&k).unwrap().unwrap();
        let s2 = p.get_keyslot(&k).unwrap().unwrap();
        assert_eq!(s1.index(), s2.index());
    }
    assert_eq!(ops.programmed.lock().len(), 1);
}

#[test]
fn distinct_keys_take_distinct_slots() {
    let ops = rec(false);
    let p = profile(ops.clone(), 4, KeyTypes::RAW);
    let a = raw_key(Mode::Aes256Xts, 1, 4096);
    let b = raw_key(Mode::Aes256Xts, 2, 4096);
    let sa = p.get_keyslot(&a).unwrap().unwrap();
    let sb = p.get_keyslot(&b).unwrap().unwrap();
    assert_ne!(sa.index(), sb.index());
    assert_eq!(ops.programmed.lock().len(), 2);
}

#[test]
fn a_device_without_slots_never_sees_a_program() {
    let ops = rec(false);
    let p = profile(ops.clone(), 0, KeyTypes::RAW);
    let k = raw_key(Mode::Aes256Xts, 1, 4096);
    assert!(p.get_keyslot(&k).unwrap().is_none());
    assert!(ops.programmed.lock().is_empty());
    // Its eviction still reaches the driver, because whatever lies beneath it
    // may still hold the key, and the slot number does not exist.
    p.evict_key(&k).unwrap();
    assert_eq!(*ops.evicted.lock(), vec![None]);
}

#[test]
fn eviction_frees_the_slot_for_the_next_key() {
    let ops = rec(false);
    let p = profile(ops.clone(), 1, KeyTypes::RAW);
    let a = raw_key(Mode::Aes256Xts, 1, 4096);
    let b = raw_key(Mode::Aes256Xts, 2, 4096);
    drop(p.get_keyslot(&a).unwrap());
    p.evict_key(&a).unwrap();
    assert_eq!(*ops.evicted.lock(), vec![Some(0)]);
    drop(p.get_keyslot(&b).unwrap());
    assert_eq!(ops.programmed.lock().len(), 2);
}

#[test]
fn a_key_in_flight_cannot_be_evicted() {
    let p = profile(rec(false), 2, KeyTypes::RAW);
    let k = raw_key(Mode::Aes256Xts, 1, 4096);
    let held = p.get_keyslot(&k).unwrap().unwrap();
    // Reporting success would tell the caller it may free key material the
    // device is still reading.
    assert_eq!(p.evict_key(&k).err(), Some(BlockError::Ebusy));
    drop(held);
    p.evict_key(&k).unwrap();
}

#[test]
fn evicting_a_resident_key_is_not_an_error() {
    let ops = rec(false);
    let p = profile(ops.clone(), 2, KeyTypes::RAW);
    // There are more keys than slots, so a key not doing I/O has no reason to
    // be in one — and being asked to evict it is routine, not a fault.
    p.evict_key(&raw_key(Mode::Aes256Xts, 9, 4096)).unwrap();
    assert!(ops.evicted.lock().is_empty());
}

#[test]
fn wrapped_key_operations_are_refused_by_a_raw_only_device() {
    let p = profile(rec(true), 2, KeyTypes::RAW);
    // The controller here CAN unwrap; the profile does not advertise that it
    // takes wrapped keys, so the request must not reach the controller.
    assert_eq!(p.derive_sw_secret(&[1, 2, 3]).err(), Some(BlockError::Eopnotsupp));
    assert_eq!(p.import_key(&[0u8; 32]).err(), Some(BlockError::Eopnotsupp));
    assert_eq!(p.generate_key().err(), Some(BlockError::Eopnotsupp));
    assert_eq!(p.prepare_key(&[0u8; 32]).err(), Some(BlockError::Eopnotsupp));
}

#[test]
fn a_wrapped_key_device_derives_and_refuses_what_it_lacks() {
    let p = profile(rec(true), 2, KeyTypes::RAW | KeyTypes::HW_WRAPPED);
    let s = p.derive_sw_secret(&[7u8; 32]).unwrap();
    assert_eq!(s, [7u8 ^ 0x5a; SW_SECRET_SIZE]);
    // Wrapped keys are advertised, but this controller implements no
    // long-term key management, so those still refuse rather than pretend.
    assert_eq!(p.import_key(&[0u8; 32]).err(), Some(BlockError::Eopnotsupp));
    assert_eq!(p.generate_key().err(), Some(BlockError::Eopnotsupp));
}

#[test]
fn intersecting_with_a_child_only_ever_removes() {
    let mut parent = Profile::new(rec(false) as Arc<dyn LlOps>, 0)
        .with_mode_range(Mode::Aes256Xts, 512, 4096).unwrap()
        .with_mode(Mode::Adiantum, 4096)
        .with_max_dun_bytes(16)
        .with_key_types(KeyTypes::RAW | KeyTypes::HW_WRAPPED);
    let child = profile(rec(false), 0, KeyTypes::RAW);
    parent.intersect(Some(&child));
    assert!(parent.supports(&cfg(Mode::Aes256Xts, 4096, 8, KeyType::Raw)));
    assert!(!parent.supports(&cfg(Mode::Aes256Xts, 512, 8, KeyType::Raw)));
    assert!(!parent.supports(&cfg(Mode::Adiantum, 4096, 8, KeyType::Raw)));
    assert!(!parent.supports(&cfg(Mode::Aes256Xts, 4096, 8, KeyType::HwWrapped)));
    assert!(parent.has_capabilities(&child) || !child.has_capabilities(&parent));
}

#[test]
fn intersecting_with_no_child_leaves_nothing() {
    let mut p = profile(rec(false), 0, KeyTypes::RAW);
    p.intersect(None);
    assert!(!p.supports(&cfg(Mode::Aes256Xts, 4096, 8, KeyType::Raw)));
    assert_eq!(p.key_types(), KeyTypes::empty());
}
