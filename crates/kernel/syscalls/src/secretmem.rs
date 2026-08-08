// memfd_secret(2) admission — `SYSCALL_DEFINE1(memfd_secret)`.
//
// NOT target-gated so the hosted suite reaches the ladder; `447_memfd_secret.rs`
// is the shim.
//
// The syscall's entire contract is that its pages are removed from the kernel's
// linear map. Where that is impossible the answer is ENOSYS rather than an
// ordinary page of RAM handed back under a name that promises otherwise.
//
// Whether it is possible is a property of the ARCHITECTURE's ability to change
// a live kernel mapping's granularity — not of the granularity the map happens
// to have been built at. Reading it the second way answers "no" on a machine
// that can do it perfectly well, and the only visible effect is a syscall that
// reports itself unimplemented for no reason.

use syscall::errno::Errno;
use vfs::OpenFlags;

/// `SECRETMEM_MODE_MASK` / `SECRETMEM_FLAGS_MASK` — no
/// mode bits are defined, so `O_CLOEXEC` is the only accepted flag.
pub const SECRETMEM_FLAGS_MASK: u32 = 0;

/// Whether single pages can be removed from this machine's kernel linear map.
/// # C: O(1)
pub fn can_set_direct_map() -> bool { pmm::setup::can_set_direct_map() }

/// `memfd_secret`'s admission, in order: the direct-map capability first, then
/// the flag mask, then the live-file count. `Ok(cloexec)` reports whether the
/// returned descriptor carries `FD_CLOEXEC`.
///
/// Note the flag is `O_CLOEXEC` (0o2000000), NOT `FD_CLOEXEC` (1) and not
/// `MFD_CLOEXEC` (1): `memfd_secret` shares no flag space with `memfd_create`,
/// which is why routing it into the latter mangles both the accepted set and
/// the errno.
/// # C: O(1)
pub fn memfd_secret_check(flags: u32) -> Result<bool, Errno> {
    if !can_set_direct_map() { return Err(Errno::Enosys); }
    let cloexec = OpenFlags::O_CLOEXEC.bits() as u32;
    if flags & !(SECRETMEM_FLAGS_MASK | cloexec) != 0 { return Err(Errno::Einval); }
    if !::fs::secretmem::secretmem_can_create() { return Err(Errno::Enfile); }
    Ok(flags & cloexec != 0)
}

/// The mapping-time half of a secret-memory file. A mapping that is not
/// shared is refused: there is no private copy to make, because the pages are
/// absent from the kernel's linear map. What comes back are the VMA
/// properties the file imposes whatever the caller asked — the pages can be
/// neither reclaimed nor written to a core dump, and the mapping is therefore
/// charged against the memlock limit like any other locked one.
/// # C: O(1)
pub fn secretmem_mmap_prepare(shared: bool) -> Result<vmm::VmaFlags, Errno> {
    if !shared { return Err(Errno::Einval); }
    Ok(vmm::VmaFlags::LOCKED | vmm::VmaFlags::DONTDUMP | vmm::VmaFlags::SECRETMEM)
}

#[cfg(test)]
mod tests {
    use super::*;

    const O_CLOEXEC: u32 = 0o2000000;

    #[test]
    fn a_private_mapping_of_secret_memory_is_refused() {
        assert_eq!(secretmem_mmap_prepare(false), Err(Errno::Einval));
    }

    #[test]
    fn a_shared_mapping_is_locked_and_never_dumped_whether_asked_for_or_not() {
        let f = secretmem_mmap_prepare(true).expect("a shared mapping is admitted");
        assert!(f.contains(vmm::VmaFlags::LOCKED),
                "a page absent from the linear map can never be reclaimed, so the mapping is locked");
        assert!(f.contains(vmm::VmaFlags::DONTDUMP),
                "and must not be written into a core dump");
        assert!(f.contains(vmm::VmaFlags::SECRETMEM),
                "and must be identifiable afterwards, so a pin of it can be refused");
    }

    #[test]
    fn o_cloexec_is_the_flag_memfd_secret_takes_not_mfd_cloexec() {
        assert_eq!(OpenFlags::O_CLOEXEC.bits() as u32, O_CLOEXEC);
        // MFD_CLOEXEC is 1 and means nothing here; routing memfd_secret into
        // memfd_create made `memfd_secret(O_CLOEXEC)` an undefined MFD bit.
        assert_ne!(O_CLOEXEC, 1);
    }

    /// The capability is not a statement about how large the linear map's
    /// leaves are. A map built from the largest leaves that fit is the normal
    /// case and does not make the syscall unavailable, because the leaf
    /// covering a page is broken down on demand.
    #[test]
    fn the_capability_is_not_a_claim_about_leaf_size() {
        let map_built_at: u64 = 1 << 30;
        assert_ne!(map_built_at, hal::PAGE_SIZE_BYTES);
        assert!(can_set_direct_map());
    }

    #[test]
    fn the_flag_ladder_accepts_only_cloexec() {
        assert_eq!(memfd_secret_check(0), Ok(false));
        assert_eq!(memfd_secret_check(O_CLOEXEC), Ok(true));
        assert_eq!(memfd_secret_check(1), Err(Errno::Einval), "MFD_CLOEXEC is not a memfd_secret flag");
        assert_eq!(memfd_secret_check(O_CLOEXEC | 2), Err(Errno::Einval));
        assert_eq!(memfd_secret_check(0xdead_beef), Err(Errno::Einval));
    }
}
