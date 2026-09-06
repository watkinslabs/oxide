use super::*;

#[test]
fn extra_class_encoding_is_copied_to_each_canonical_window() {
    let mut manager = WindowManager::new();
    let ansi = manager.register_class_with_encoding(&[65], 0x1000, 8, false).unwrap();
    let wide = manager.register_class_with_extra(&[87], 0x2000, 8).unwrap();
    let a = manager.create_class_atom(7, None, ansi).unwrap();
    let w = manager.create_class_atom(7, None, wide).unwrap();
    assert!(!manager.get(a).unwrap().unicode);
    assert!(manager.get(w).unwrap().unicode);
    assert_eq!(manager.set_window_long_with_encoding(a, -4, 8, 0x3000, true), Ok(0x1000));
    assert!(manager.get(a).unwrap().unicode);
    assert_eq!(manager.set_window_long_with_encoding(a, -4, 4, 1 << 32, false), Ok(0x3000));
    assert!(manager.get(a).unwrap().unicode);
    assert_eq!(manager.get(a).unwrap().wndproc, 0x3000);
}

#[test]
fn extra_edit_state_pointer_round_trip_and_previous_value() {
    let mut bytes = WindowExtra::new(8, 0x1800_0000).unwrap();
    assert_eq!(bytes.read(0, 8), Ok(0));
    assert_eq!(bytes.write(0, 8, 0x7f65_1234_5678), Ok(0));
    assert_eq!(bytes.read(0, 8), Ok(0x7f65_1234_5678));
    assert_eq!(bytes.write(0, 8, 0), Ok(0x7f65_1234_5678));
    assert_eq!(bytes.userdata, 0);
    assert_eq!(bytes.instance, 0x1800_0000);
}

#[test]
fn extra_unaligned_overlapping_ranges_are_byte_indexed() {
    let mut bytes = WindowExtra::new(12, 0).unwrap();
    bytes.write(1, 8, 0x8877_6655_4433_2211).unwrap();
    assert_eq!(bytes.read(2, 4), Ok(0x5544_3322));
    assert_eq!(bytes.write(4, 2, 0xffff_aa99), Ok(0x5544));
    assert_eq!(bytes.read(1, 8), Ok(0x8877_66aa_9933_2211));
    assert_eq!(bytes.read(0, 2), Ok(0x1100));
}

#[test]
fn extra_extent_and_invalid_access_never_mutate() {
    assert!(matches!(WindowExtra::new(-1, 0), Err(LongPtrError::InvalidSize)));
    assert!(matches!(WindowExtra::new(4097, 0), Err(LongPtrError::InvalidSize)));
    let mut empty = WindowExtra::new(0, 0).unwrap();
    assert_eq!(empty.write(0, 8, 1), Err(LongPtrError::InvalidIndex));
    let mut bytes = WindowExtra::new(4096, 0).unwrap();
    assert_eq!(bytes.len(), 4096);
    assert_eq!(bytes.write(4088, 8, u64::MAX), Ok(0));
    for (offset, width) in [(-1, 8), (4089, 8), (4096, 2), (i32::MAX, 8)] {
        assert_eq!(bytes.write(offset, width, 0), Err(LongPtrError::InvalidIndex));
    }
    for width in [0, 1, 3, 16, usize::MAX] {
        assert_eq!(bytes.write(0, width, 0), Err(LongPtrError::InvalidSize));
    }
    assert_eq!(bytes.read(4088, 8), Ok(u64::MAX));
    assert_eq!(bytes.read(0, 8), Ok(0));
}

#[test]
fn extra_window_storage_is_independent() {
    let mut first = WindowExtra::new(8, 1).unwrap();
    let second = WindowExtra::new(8, 2).unwrap();
    first.write(0, 8, u64::MAX).unwrap();
    assert_eq!(second.read(0, 8), Ok(0));
    drop(first);
    assert_eq!(WindowExtra::new(8, 1).unwrap().read(0, 8), Ok(0));
}

#[test]
fn extra_actual_owner_edit_state_and_procedure_dispatch_identity() {
    let mut manager = WindowManager::new();
    let atom = manager.register_class_with_extra(&[69, 68, 73, 84], 0x1000, 8).unwrap();
    let window = manager.create_class_atom(7, None, atom).unwrap();
    assert_eq!(manager.get_window_long_ptr(window, 0), Ok(0));
    manager.set_window_long_ptr(window, GWLP_HINSTANCE, 0x1800_0000).unwrap();
    assert_eq!(manager.set_window_long_ptr(window, 0, 0x7f65_1234_5678), Ok(0));
    assert_eq!(manager.get_window_long_ptr(window, 0), Ok(0x7f65_1234_5678));
    assert_eq!(manager.get_window_long(window, 0, 4), Ok(0x1234_5678));
    assert_eq!(manager.set_window_long_ptr(window, GWLP_WNDPROC, 0x2000), Ok(0x1000));
    assert_eq!(manager.get(window).unwrap().wndproc, 0x2000);
    assert_eq!(manager.set_window_long_ptr(window, GWLP_WNDPROC, 0), Ok(0x2000));
    assert_eq!(manager.set_window_long(window, GWLP_WNDPROC, 4, 0x1234_0000_0000), Ok(0x2000));
    assert_eq!(manager.get(window).unwrap().wndproc, 0x2000);
    manager.destroy(window).unwrap();
    assert_eq!(manager.get_window_long_ptr(window, 0), Err(LongPtrError::InvalidWindow));
}

#[test]
fn extra_class_bounds_zero_defaults_and_per_window_allocation() {
    let mut manager = WindowManager::new();
    for size in [-1, 4097, i32::MAX] {
        assert_eq!(manager.register_class_with_extra(&[65], 1, size), Err(super::super::WindowError::InvalidParent));
    }
    let atom = manager.register_class_with_extra(&[65], 1, 4096).unwrap();
    assert_eq!(atom, 1);
    assert_eq!(manager.class_extra_by_atom(atom), Some(4096));
    assert_eq!(manager.class_extra_by_atom(0), None);
    let first = manager.create_class(7, None, &[65]).unwrap();
    let second = manager.create_class_atom(7, None, atom).unwrap();
    assert_eq!(manager.set_window_long_ptr(first, 4088, u64::MAX), Ok(0));
    assert_eq!(manager.get_window_long_ptr(second, 4088), Ok(0));
    assert_eq!(manager.set_window_long_ptr(first, 4089, 1), Err(LongPtrError::InvalidIndex));
    manager.destroy(first).unwrap();
    manager.destroy(second).unwrap();
    manager.unregister_class(&[65]).unwrap();
    assert_eq!(manager.class_extra_by_atom(atom), None);
    let zero = manager.register_class(&[65], 1).unwrap();
    assert_eq!(manager.class_extra_by_atom(zero), Some(0));
    let window = manager.create_class_atom(7, None, zero).unwrap();
    assert_eq!(manager.get_window_long_ptr(window, 0), Err(LongPtrError::InvalidIndex));
}

#[test]
fn extra_scalar_widths_id_on_nonchild_and_transaction_rejection() {
    let mut manager = WindowManager::new();
    let window = manager.create(7, None, 0x1000).unwrap();
    for offset in [GWLP_USERDATA, GWLP_HINSTANCE, GWLP_ID] {
        assert_eq!(manager.set_window_long_ptr(window, offset, 0x1122_3344_5566_7788), Ok(0));
        assert_eq!(manager.get_window_long_ptr(window, offset), Ok(0x1122_3344_5566_7788));
        assert_eq!(manager.get_window_long(window, offset, 4), Ok(0x5566_7788));
    }
    assert_eq!(manager.get(window).unwrap().id_menu, 0x1122_3344_5566_7788);
    assert_eq!(manager.set_window_long(window, GWLP_USERDATA, 2, 0xabcd), Ok(0x7788));
    assert_eq!(manager.get_window_long_ptr(window, GWLP_USERDATA), Ok(0x5566_abcd));
    assert_eq!(manager.set_window_long(window, GWLP_USERDATA, 4, 0x8765_4321), Ok(0x5566_abcd));
    assert_eq!(manager.get_window_long_ptr(window, GWLP_USERDATA), Ok(0xffff_ffff_8765_4321));
    let before = manager.get(window).unwrap();
    for offset in [GWL_STYLE, GWL_EXSTYLE, GWLP_HWNDPARENT] {
        assert_eq!(manager.set_window_long_ptr(window, offset, 12), Err(LongPtrError::OwnerTransaction));
        assert_eq!(manager.get(window), Some(before));
    }
    assert_eq!(manager.set_window_long_ptr(window, -99, 1), Err(LongPtrError::InvalidIndex));
    assert_eq!(manager.set_window_long(window, GWLP_ID, 2, 1), Err(LongPtrError::InvalidIndex));
    assert_eq!(manager.get_window_long(window, GWLP_ID, 2), Err(LongPtrError::InvalidIndex));
}
