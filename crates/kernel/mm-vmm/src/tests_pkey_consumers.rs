// The consumers of the mm's per-mapping policy answers — protection keys and
// secret memory — driven through a real address space. Each answer is
// unit-tested next to its own decision; these pin that the mm actually ASKS
// it. A correct answer nobody consults is the defect this project sees most
// often.
//
// A hosted mm models a boot with no rights register, so each test first tells
// the mm its hardware IS live; otherwise every key answer would be "permitted"
// for the wrong reason.

use hal::UserVirtAddr;

use crate::pkeys::{AARCH64, PkeyArch, X86_64};
use crate::{AddressSpace, VmaBacking, VmaFlags, VmaProt};

const PAGE: usize = hal::PAGE_SIZE_BYTES as usize;

fn va(raw: u64) -> UserVirtAddr { UserVirtAddr::new(raw).expect("test user VA") }

/// One anonymous readable mapping at a fixed address, in an mm whose rights
/// register is live.
fn mm_with_mapping(arch: PkeyArch) -> alloc::sync::Arc<AddressSpace> {
    let mm = AddressSpace::new(0).unwrap();
    mm.pkeys().force_arch_for_test(arch);
    mm.mmap(Some(va(0x4000)), PAGE, VmaProt::READ | VmaProt::WRITE,
            VmaFlags::PRIVATE | VmaFlags::ANONYMOUS, VmaBacking::Anonymous, true)
      .expect("test mapping");
    mm
}

#[test]
fn a_pin_of_a_key_denied_page_is_refused_even_though_the_vma_is_readable() {
    for arch in [PkeyArch { max_pkey: 16, ..X86_64 }, PkeyArch { alloc_checks_hw: false, ..AARCH64 }] {
        let mm = mm_with_mapping(arch);
        assert!(mm.gup_read_permitted(0x4000, |_, _, _| true),
                "a permitting register must not block the pin");
        assert!(!mm.gup_read_permitted(0x4000, |_, _, _| false),
                "the pin has no hardware check of its own, so a denying register must stop it here");
    }
}

#[test]
fn a_pin_asks_about_the_vmas_own_key_as_a_data_read() {
    let arch = PkeyArch { max_pkey: 16, ..X86_64 };
    let mm = mm_with_mapping(arch);
    // Move the mapping onto a non-default key the way pkey_mprotect would.
    mm.mprotect_user(va(0x4000), PAGE, VmaProt::READ, false, &mut |_: &crate::Vma| 5u8).unwrap();
    let seen = core::cell::Cell::new(None);
    assert!(mm.gup_read_permitted(0x4000, |k, w, x| { seen.set(Some((k, w, x))); true }));
    assert_eq!(seen.get(), Some((5u8, false, false)),
               "a pin is a data read for this mm, never a write and never an instruction fetch");
}

#[test]
fn an_unreadable_or_unmapped_range_is_refused_before_any_key_is_consulted() {
    let arch = PkeyArch { max_pkey: 16, ..X86_64 };
    let mm = mm_with_mapping(arch);
    let seen = core::cell::Cell::new(false);
    assert!(!mm.gup_read_permitted(0x9_0000, |_, _, _| { seen.set(true); true }), "unmapped");
    mm.mprotect_user(va(0x4000), PAGE, VmaProt::WRITE, false, &mut |v: &crate::Vma| v.pkey).unwrap();
    assert!(!mm.gup_read_permitted(0x4000, |_, _, _| { seen.set(true); true }), "not readable");
    assert!(!seen.get(), "the mapping tests run before the key test");
}

#[test]
fn a_boot_without_a_rights_register_never_consults_one() {
    let mm = AddressSpace::new(0).unwrap();
    mm.mmap(Some(va(0x4000)), PAGE, VmaProt::READ,
            VmaFlags::PRIVATE | VmaFlags::ANONYMOUS, VmaBacking::Anonymous, true).unwrap();
    let seen = core::cell::Cell::new(false);
    assert!(mm.gup_read_permitted(0x4000, |_, _, _| { seen.set(true); false }));
    assert!(!seen.get());
}

#[test]
fn a_pin_of_secret_memory_is_refused_however_permissive_the_key_is() {
    let arch = PkeyArch { max_pkey: 16, ..X86_64 };
    let mm = mm_with_mapping(arch);
    // The mapping is readable and the register permits everything ...
    assert!(mm.gup_read_permitted(0x4000, |_, _, _| true));
    // ... but a page with no kernel-visible address can never be pinned.
    mm.update_flags_range(va(0x4000), PAGE, VmaFlags::SECRETMEM, VmaFlags::empty());
    assert!(!mm.gup_read_permitted(0x4000, |_, _, _| true));
}

#[test]
fn a_secret_memory_mapping_can_never_be_unlocked() {
    let mm = AddressSpace::new(0).unwrap();
    mm.mmap(Some(va(0x4000)), PAGE, VmaProt::READ,
            VmaFlags::SHARED, VmaBacking::Anonymous, true).unwrap();
    mm.update_flags_range(va(0x4000), PAGE,
                          VmaFlags::SECRETMEM | VmaFlags::LOCKED, VmaFlags::empty());
    assert!(mm.find_vma(va(0x4000)).unwrap().flags.contains(VmaFlags::LOCKED));
    // The unlock the caller asked for is dropped, and every other flag change
    // in the same call still applies.
    mm.update_flags_range(va(0x4000), PAGE, VmaFlags::DONTDUMP,
                          VmaFlags::LOCKED | VmaFlags::LOCKONFAULT);
    let v = mm.find_vma(va(0x4000)).unwrap();
    assert!(v.flags.contains(VmaFlags::LOCKED), "secret memory stays locked");
    assert!(v.flags.contains(VmaFlags::DONTDUMP), "unrelated flags still change");
}
