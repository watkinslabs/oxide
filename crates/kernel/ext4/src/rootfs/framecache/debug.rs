// Feature-gated page-fill diagnostics. Kept separate from the frame-store
// state machine so debug observability remains available without growing it.

/// Stable diagnostic name for a frame fill failure. # C: O(1)
#[cfg(feature = "debug-fillverify")]
pub(super) fn fill_error_label(error: crate::MountError) -> &'static [u8] {
    match error {
        crate::MountError::BlockIo => b"block-io",
        crate::MountError::Superblock(_) => b"superblock",
        crate::MountError::Gdt(_) => b"gdt",
        crate::MountError::Inode(_) => b"inode",
        crate::MountError::Dir(_) => b"directory",
        crate::MountError::NotFound => b"not-found",
        crate::MountError::NotDir => b"not-directory",
        crate::MountError::NotExtents => b"not-extents",
        crate::MountError::DepthUnsupported => b"extent-depth",
        crate::MountError::NoSpace => b"no-space",
        crate::MountError::BadBlock => b"bad-block",
        crate::MountError::DoubleFree => b"double-free",
        crate::MountError::ExtentTreeFull => b"extent-tree-full",
        crate::MountError::DirFull => b"directory-full",
        crate::MountError::CorruptExtentTree => b"corrupt-extent-tree",
        crate::MountError::BadChecksum => b"bad-checksum",
        crate::MountError::UnsupportedFeature => b"unsupported-feature",
        crate::MountError::Quota(_) => b"quota",
    }
}

/// Cheap checksum over one page's HHDM frame mirror. # C: O(PAGE_SIZE)
#[cfg(feature = "debug-fillverify")]
pub(super) fn page_sum(base: *const u8) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    // SAFETY: caller supplies a live frame mirror; the loop is exactly PAGE_SIZE.
    unsafe {
        let words = base as *const u64;
        for i in 0..(hal::PAGE_SIZE_BYTES as usize / core::mem::size_of::<u64>()) {
            h ^= core::ptr::read_volatile(words.add(i));
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}
