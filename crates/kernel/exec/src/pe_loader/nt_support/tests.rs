use super::*;
use vmm::AddressSpace;

#[test]
fn layout_is_contiguous_and_ordered() {
    let at = support_offsets();
    assert_eq!(at.run_once_continuation, 0);
    assert!(at.run_once_continuation < at.wndproc_continuation);
    assert!(at.wndproc_continuation < at.apc_continuation);
    assert!(at.apc_continuation < at.syscall_dispatcher_slot);
    assert_eq!(at.unix_call_dispatcher_slot, at.syscall_dispatcher_slot + SLOT_BYTES);
    assert_eq!(at.unixlib_handle_slot, at.syscall_dispatcher_slot + 2 * SLOT_BYTES);
    assert_eq!(at.relay_call, at.syscall_dispatcher_slot + DATA_SLOT_COUNT * SLOT_BYTES);
    assert!(at.relay_call < at.wine_dispatcher);
    assert!(at.wine_dispatcher < at.wine_unix_dispatcher);
    assert_eq!(at.table, at.unixlib_handle_datum + SLOT_BYTES);
    assert_eq!(at.table_end, at.table + syscall::nt_wine_unix::WINE_UNIX_FUNCTION_COUNT * SLOT_BYTES);
    assert_eq!(at.bytes, at.table_end);
}

#[test]
fn region_slots_point_at_the_regions_own_trampolines() {
    const BASE: u64 = 0x7f00_0000;
    let at = support_offsets();
    let region = build_support_region(BASE).unwrap();
    assert_eq!(region.len(), at.bytes);
    let slot = |offset: usize| u64::from_le_bytes(region[offset..offset + SLOT_BYTES].try_into().unwrap());
    assert_eq!(slot(at.syscall_dispatcher_slot), BASE + at.wine_dispatcher as u64);
    assert_eq!(slot(at.unix_call_dispatcher_slot), BASE + at.wine_unix_dispatcher as u64);
    assert_eq!(slot(at.unixlib_handle_slot), syscall::nt::WINE_UNIXLIB_HANDLE);
    assert_eq!(slot(at.unixlib_handle_datum), syscall::nt::WINE_UNIXLIB_HANDLE);
    for entry in 0..syscall::nt_wine_unix::WINE_UNIX_FUNCTION_COUNT {
        assert_eq!(slot(at.table + entry * SLOT_BYTES), BASE + at.wine_unix_dispatcher as u64);
    }
}

#[test]
fn no_published_item_is_null_or_outside_the_region() {
    const BASE: u64 = 0x6000_0000;
    let support = describe(BASE, None).unwrap();
    let end = BASE + support.bytes;
    for address in [support.run_once_continuation, support.wndproc_continuation, support.apc_continuation,
        support.relay_call, support.wine_dispatcher, support.wine_unix_dispatcher,
        support.syscall_dispatcher_slot, support.unix_call_dispatcher_slot,
        support.unixlib_handle_slot, support.unixlib_handle_datum, support.table_address] {
        assert!(address >= BASE && address < end);
    }
    assert!(support.wndproc_continuation != support.run_once_continuation);
    assert!(support.apc_continuation != support.wndproc_continuation);
    assert!(support.wine_dispatcher != support.wine_unix_dispatcher);
}

#[test]
fn continuations_resolve_from_the_address_space_not_from_a_module_base() {
    let as_ = AddressSpace::new(0x7_3100).unwrap();
    let root = as_.root_pa();
    assert_eq!(run_once_continuation(root), None);
    assert_eq!(wndproc_continuation(root), None);
    assert_eq!(apc_continuation(root), None);
    let support = map_and_publish(&as_).unwrap();
    assert_eq!(run_once_continuation(root), Some(support.run_once_continuation));
    assert_eq!(wndproc_continuation(root), Some(support.wndproc_continuation));
    assert_eq!(apc_continuation(root), Some(support.apc_continuation));
    // The handover maps a real runtime module, so no module may be answered
    // by page arithmetic.
    assert!(!is_synthetic_module(root, support.base));
    crate::elf_modules::clear(root);
}

#[test]
fn publication_registers_the_unix_call_table_the_bootstrap_handle_names() {
    let as_ = AddressSpace::new(0x7_3200).unwrap();
    let root = as_.root_pa();
    assert_eq!(crate::elf_modules::unixlib_descriptor(root), None);
    let support = map_and_publish(&as_).unwrap();
    let descriptor = crate::elf_modules::unixlib_descriptor(root).unwrap();
    assert_eq!(descriptor.table_address, support.table_address);
    assert_eq!(descriptor.entries, alloc::vec![support.wine_unix_dispatcher; syscall::nt_wine_unix::WINE_UNIX_FUNCTION_COUNT]);
    crate::elf_modules::clear(root);
}

#[test]
fn a_synthetic_page_claims_only_its_own_module() {
    let as_ = AddressSpace::new(0x7_3300).unwrap();
    let root = as_.root_pa();
    let support = publish(&as_, 0x9000_0000, 0x9001_0000, Some(0x8000_0000)).unwrap();
    assert!(is_synthetic_module(root, 0x8000_0000));
    assert!(!is_synthetic_module(root, 0x8001_0000));
    assert_eq!(support.synthetic_module, Some(0x8000_0000));
    crate::elf_modules::clear(root);
}
