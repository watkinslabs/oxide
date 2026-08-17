// Resource-manager space. The property under test is isolation: a file can
// only name what it loaded, and closing it releases exactly that.

use crate::limits::{SPACE_BUFFER_SIZE, SPACE_CONTEXT_SLOTS, SPACE_SESSION_SLOTS};
use crate::space::{Space, SpaceError};
use crate::uapi::{TPM2_HT_HMAC_SESSION, TPM2_HT_POLICY_SESSION, TPM2_HT_TRANSIENT};

#[test]
fn virtual_handles_sit_at_the_top_of_the_transient_range() {
    assert_eq!(Space::vhandle_of_slot(0), 0x80FF_FFFF);
    assert_eq!(Space::vhandle_of_slot(1), 0x80FF_FFFE);
    for i in 0..SPACE_CONTEXT_SLOTS {
        let v = Space::vhandle_of_slot(i);
        assert!(Space::is_transient(v));
        assert_eq!(Space::slot_of_vhandle(v), Some(i));
    }
    assert_eq!(Space::slot_of_vhandle(0x8000_0000), None);
    assert_eq!(Space::slot_of_vhandle(0x0200_0000), None);
}

#[test]
fn a_bound_object_resolves_only_through_its_own_space() {
    let mut a = Space::new(SPACE_BUFFER_SIZE);
    let mut b = Space::new(SPACE_BUFFER_SIZE);
    let v = a.bind(0x8000_0001).unwrap();
    assert_eq!(a.resolve(v).unwrap(), 0x8000_0001);
    // The other space knows nothing of that virtual handle, so a file cannot
    // reach another file's object by naming its number.
    assert_eq!(b.resolve(v), Err(SpaceError::UnknownHandle(v)));
    let _ = b.bind(0x8000_0002).unwrap();
    assert_eq!(b.resolve(v).unwrap(), 0x8000_0002);
    assert_ne!(a.resolve(v).unwrap(), b.resolve(v).unwrap());
}

#[test]
fn an_unbound_virtual_handle_resolves_to_nothing() {
    let s = Space::new(SPACE_BUFFER_SIZE);
    let v = Space::vhandle_of_slot(0);
    assert_eq!(s.resolve(v), Err(SpaceError::UnknownHandle(v)));
    assert_eq!(s.resolve(0x8000_0001), Err(SpaceError::UnknownHandle(0x8000_0001)));
}

#[test]
fn object_slots_are_bounded() {
    let mut s = Space::new(SPACE_BUFFER_SIZE);
    for i in 0..SPACE_CONTEXT_SLOTS { s.bind(0x8000_0000 + i as u32).unwrap(); }
    assert_eq!(s.bind(0x8000_00FF), Err(SpaceError::NoSlots));
    assert_eq!(s.loaded().len(), SPACE_CONTEXT_SLOTS);
}

#[test]
fn session_slots_are_bounded_and_forgettable() {
    let mut s = Space::new(SPACE_BUFFER_SIZE);
    for i in 0..SPACE_SESSION_SLOTS { s.add_session(TPM2_HT_HMAC_SESSION | i as u32).unwrap(); }
    assert_eq!(s.add_session(TPM2_HT_HMAC_SESSION | 0xFF), Err(SpaceError::NoSlots));
    s.forget_session(TPM2_HT_HMAC_SESSION);
    assert_eq!(s.sessions().len(), SPACE_SESSION_SLOTS - 1);
    s.add_session(TPM2_HT_HMAC_SESSION | 0xFF).unwrap();
}

#[test]
fn handle_kinds_are_recognised() {
    assert!(Space::is_transient(TPM2_HT_TRANSIENT | 1));
    assert!(!Space::is_transient(TPM2_HT_HMAC_SESSION | 1));
    assert!(Space::is_session(TPM2_HT_HMAC_SESSION | 1));
    assert!(Space::is_session(TPM2_HT_POLICY_SESSION | 1));
    assert!(!Space::is_session(TPM2_HT_TRANSIENT | 1));
    assert!(!Space::is_session(0x4000_0009));
}

#[test]
fn a_saved_object_stops_resolving_until_it_is_reloaded() {
    let mut s = Space::new(SPACE_BUFFER_SIZE);
    let v = s.bind(0x8000_0001).unwrap();
    s.save(0, &[0xAB; 64]).unwrap();
    assert_eq!(s.context_buf().len(), 64);
    assert_eq!(s.resolve(v), Err(SpaceError::UnknownHandle(v)));
    assert!(s.loaded().is_empty());
    s.reload(0, 0x8000_0007).unwrap();
    assert_eq!(s.resolve(v).unwrap(), 0x8000_0007);
}

#[test]
fn saved_state_is_bounded_by_the_backing_store() {
    let mut s = Space::new(32);
    s.bind(0x8000_0001).unwrap();
    assert_eq!(s.save(0, &[0u8; 64]), Err(SpaceError::NoStorage));
    assert_eq!(s.save_session(&[0u8; 64]), Err(SpaceError::NoStorage));
    s.save(0, &[0u8; 32]).unwrap();
    assert_eq!(s.save(0, &[0u8; 1]), Err(SpaceError::NoStorage));
}

#[test]
fn closing_a_space_releases_everything_it_loaded() {
    let mut s = Space::new(SPACE_BUFFER_SIZE);
    s.bind(0x8000_0001).unwrap();
    s.bind(0x8000_0002).unwrap();
    s.add_session(TPM2_HT_HMAC_SESSION | 3).unwrap();
    s.save_session(&[0xCD; 8]).unwrap();
    let flushed = s.close();
    assert_eq!(flushed, [0x8000_0001, 0x8000_0002, TPM2_HT_HMAC_SESSION | 3]);
    assert!(s.loaded().is_empty());
    assert!(s.sessions().is_empty());
    assert!(s.context_buf().is_empty());
    assert!(s.session_buf().is_empty());
    // The slots are reusable and resolve to nothing until rebound.
    let v = Space::vhandle_of_slot(0);
    assert_eq!(s.resolve(v), Err(SpaceError::UnknownHandle(v)));
}

#[test]
fn a_physical_handle_can_be_mapped_back_to_its_virtual_name() {
    let mut s = Space::new(SPACE_BUFFER_SIZE);
    let v = s.bind(0x8000_0005).unwrap();
    assert_eq!(s.vhandle_of(0x8000_0005), Some(v));
    assert_eq!(s.vhandle_of(0x8000_0006), None);
}
