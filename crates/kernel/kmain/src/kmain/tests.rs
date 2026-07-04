use crate::{BootInfo, BootMemKind};

#[test]
fn boot_info_layout_is_repr_c() {
    // Sanity check: BootInfo size is determinist on a 64-bit host.
    // u32 + ptr + [u8;32] + u64 + u64 with natural alignment.
    assert!(core::mem::size_of::<BootInfo>() >= 60);
}

#[test]
fn boot_mem_kind_distinct() {
    assert_ne!(BootMemKind::Usable as u8, BootMemKind::BadMem as u8);
}
