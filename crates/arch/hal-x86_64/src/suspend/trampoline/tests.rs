// The resume stub's placement contract. The blob itself cannot be exercised
// hosted — it is 16-bit code that runs with paging off — but where it may be
// placed, and the refusal to place it at all until the boot path has withheld
// the page, are decisions, and both are checked here.

use super::*;

#[test]
fn the_stub_page_is_one_firmware_can_resume_at() {
    // Real mode, page-aligned, and clear of the first page.
    assert!(super::super::state::resume_vector_placeable(WAKEUP_TRAMP_PA));
    assert!(WAKEUP_TRAMP_PA < super::super::state::REAL_MODE_LIMIT);
    assert_eq!(WAKEUP_TRAMP_PA % super::super::state::RESUME_PAGE_BYTES, 0);
}

#[test]
fn the_data_block_lies_inside_the_page_and_clear_of_the_code() {
    // The 16- and 32-bit stages address these by literal, so a block that
    // overlapped the code would be patched over by the copy.
    assert!(OFF_CR3 < OFF_ENTRY);
    assert!(OFF_ENTRY < OFF_GDT);
    assert!(OFF_GDT < OFF_GDTPTR);
    assert!(OFF_GDTPTR + 8 <= TRAMP_BYTES as u64);
    // The literals the asm quotes must be the page base plus these offsets.
    assert_eq!(WAKEUP_TRAMP_PA + OFF_CR3, 0x9f00);
    assert_eq!(WAKEUP_TRAMP_PA + OFF_GDTPTR, 0x9f60);
}

#[test]
fn nothing_installs_until_the_boot_path_reserved_the_page() {
    assert!(!wakeup_page_reserved(), "the page must start unreserved");
    // SAFETY: hosted build; `install_wakeup_trampoline` writes nothing there.
    assert_eq!(unsafe { install_wakeup_trampoline() }, None);
    set_wakeup_page_reserved();
    assert!(wakeup_page_reserved());
}
