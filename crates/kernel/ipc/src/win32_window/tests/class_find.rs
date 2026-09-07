//! Keying a registration by name and module: two modules registering one name
//! get two classes, a global class answers any module, and unregistration
//! refuses a class another module owns or a class with a live window.
use super::super::*;

const NAME: [u16; 3] = [b'B' as u16, b'T' as u16, b'N' as u16];
const MOD_A: u64 = 0x0001_0000;
const MOD_B: u64 = 0x0002_0000;

fn local(module: u64, wndproc: u64) -> ClassRegistration<'static> {
    ClassRegistration { module, ..ClassRegistration::new(&NAME, wndproc) }
}

#[test]
fn two_modules_registering_one_name_get_two_classes() {
    let mut manager = WindowManager::new();
    let first = manager.register_class_desc(local(MOD_A, 0x1000)).unwrap();
    let second = manager.register_class_desc(local(MOD_B, 0x2000)).unwrap();
    assert_ne!(first, second);
    assert_eq!(manager.class_wndproc_from(&NAME, MOD_A), Some(0x1000));
    assert_eq!(manager.class_wndproc_from(&NAME, MOD_B), Some(0x2000));
    // Positive control: the same module twice is still a duplicate.
    assert_eq!(manager.register_class_desc(local(MOD_A, 0x3000)), Err(WindowError::InvalidParent));
}

#[test]
fn a_lookup_naming_no_module_takes_the_first_class() {
    let mut manager = WindowManager::new();
    manager.register_class_desc(local(MOD_A, 0x1000)).unwrap();
    manager.register_class_desc(local(MOD_B, 0x2000)).unwrap();
    assert!(manager.class_wndproc(&NAME).is_some());
    assert_eq!(manager.class_wndproc_from(&NAME, 0x0003_0000), None);
}

#[test]
fn a_global_class_is_found_without_an_instance_match() {
    let mut manager = WindowManager::new();
    let atom = manager.register_class_desc(ClassRegistration { style: CS_GLOBALCLASS, ..local(MOD_A, 0x1000) }).unwrap();
    assert_eq!(manager.find_class(&NAME, MOD_B).map(|class| class.atom), Some(atom));
    assert_eq!(manager.find_class_by_atom(atom, MOD_B).map(|class| class.atom), Some(atom));
    // A builtin registration is global whatever its style says.
    let other = [b'E' as u16];
    manager.register_class_desc(ClassRegistration { builtin: true, module: MOD_A, ..ClassRegistration::new(&other, 0x4000) }).unwrap();
    assert_eq!(manager.class_wndproc_from(&other, MOD_B), Some(0x4000));
    // Positive control: the same registration without the global marks is
    // invisible from the other module.
    let third = [b'F' as u16];
    manager.register_class_desc(ClassRegistration { module: MOD_A, ..ClassRegistration::new(&third, 0x5000) }).unwrap();
    assert_eq!(manager.class_wndproc_from(&third, MOD_B), None);
}

#[test]
fn a_module_sharing_the_high_bits_reaches_a_local_class() {
    // A 32-bit module handle matches on its high bits alone; a 16-bit one,
    // whose high bits are zero, never does.
    assert!(instance_matches(MOD_A | 0x40, true, MOD_A | 0x80));
    assert!(!instance_matches(MOD_A, true, MOD_B));
    assert!(!instance_matches(0x0040, true, 0x0080));
    assert!(instance_matches(MOD_A, false, MOD_B));
    assert!(instance_matches(MOD_A, true, 0));
}

#[test]
fn unregistering_from_the_wrong_module_is_refused() {
    let mut manager = WindowManager::new();
    manager.register_class_desc(local(MOD_A, 0x1000)).unwrap();
    assert_eq!(manager.unregister_class_from(&NAME, MOD_B), Err(WindowError::NoSuchWindow));
    // Positive control: the registering module removes it.
    assert_eq!(manager.unregister_class_from(&NAME, MOD_A), Ok(()));
    assert_eq!(manager.class_wndproc_from(&NAME, MOD_A), None);
}

#[test]
fn a_live_window_blocks_unregistration() {
    let mut manager = WindowManager::new();
    manager.register_class_desc(local(MOD_A, 0x1000)).unwrap();
    let window = manager.create_class_from(7, None, &NAME, MOD_A).unwrap();
    assert_eq!(manager.unregister_class_from(&NAME, MOD_A), Err(WindowError::ClassInUse));
    manager.destroy(window).unwrap();
    assert_eq!(manager.unregister_class_from(&NAME, MOD_A), Ok(()));
}

#[test]
fn an_extra_request_outside_the_admitted_range_is_refused() {
    let mut manager = WindowManager::new();
    assert!(extra_size_admitted(MAX_CLASS_EXTRA));
    assert!(!extra_size_admitted(MAX_CLASS_EXTRA + 1));
    assert!(!extra_size_admitted(-1));
    assert_eq!(manager.register_class_desc(ClassRegistration { cb_cls_extra: MAX_CLASS_EXTRA + 1, ..local(MOD_A, 1) }), Err(WindowError::InvalidParent));
    assert_eq!(manager.register_class_desc(ClassRegistration { cb_cls_extra: -1, ..local(MOD_A, 1) }), Err(WindowError::InvalidParent));
    assert!(manager.register_class_desc(ClassRegistration { cb_cls_extra: MAX_CLASS_EXTRA, ..local(MOD_A, 1) }).is_ok());
}
