// memfd_secret(2) admission — `SYSCALL_DEFINE1(memfd_secret)`
// (`mm/secretmem.c:224`).
//
// NOT target-gated so the hosted suite reaches the ladder; `447_memfd_secret.rs`
// is the shim.
//
// The syscall's entire contract is that its pages are removed from the
// kernel's linear map (`set_direct_map_invalid_noflush`, `mm/secretmem.c:75`)
// and restored on free (`:154`). Linux refuses to pretend otherwise: when the
// architecture cannot unmap single pages from the linear map it answers
// -ENOSYS rather than hand back ordinary RAM under a "secret" name
// (`mm/secretmem.c:229`).

use syscall::errno::Errno;
use vfs::OpenFlags;

/// `SECRETMEM_MODE_MASK` / `SECRETMEM_FLAGS_MASK` (`mm/secretmem.c:35`) — no
/// mode bits are defined, so `O_CLOEXEC` is the only accepted flag.
pub const SECRETMEM_FLAGS_MASK: u32 = 0;

/// Leaf size of oxide's HHDM. The bootloader maps phys 0..512 GiB with 512 ×
/// 1 GiB leaves (`crates/arch/boot-x86_64/src/mb2.rs:28`, x86_64) / 1 GiB
/// level-1 blocks (`crates/arch/boot-aarch64/src/selfboot.rs:15`, aarch64).
pub const HHDM_LEAF_BYTES: u64 = 1 << 30;

/// Linux `can_set_direct_map()` (`arch/arm64/mm/pageattr.c:90`): true only
/// when the linear map is at page granularity, "so that it is possible to
/// protect/unprotect single pages".
///
/// False on oxide: the HHDM is 1 GiB blocks and `hal::pt_walker` has no
/// huge-leaf split, so no single page can be removed from it.
/// # C: O(1)
pub const fn can_set_direct_map() -> bool { HHDM_LEAF_BYTES == hal::PAGE_SIZE_BYTES }

/// `memfd_secret`'s admission, in Linux's order: the direct-map capability
/// first, then the flag mask. `Ok(cloexec)` reports whether the returned
/// descriptor carries `FD_CLOEXEC`.
///
/// Note the flag is `O_CLOEXEC` (0o2000000), NOT `FD_CLOEXEC` (1) and not
/// `MFD_CLOEXEC` (1): `memfd_secret` shares no flag space with
/// `memfd_create`, which is why routing it into the latter mangles both the
/// accepted set and the errno.
/// # C: O(1)
pub fn memfd_secret_check(flags: u32) -> Result<bool, Errno> {
    if !can_set_direct_map() { return Err(Errno::Enosys); }
    let cloexec = OpenFlags::O_CLOEXEC.bits() as u32;
    if flags & !(SECRETMEM_FLAGS_MASK | cloexec) != 0 { return Err(Errno::Einval); }
    Ok(flags & cloexec != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const O_CLOEXEC: u32 = 0o2000000;

    #[test]
    fn o_cloexec_is_the_flag_memfd_secret_takes_not_mfd_cloexec() {
        assert_eq!(OpenFlags::O_CLOEXEC.bits() as u32, O_CLOEXEC);
        // MFD_CLOEXEC is 1 and means nothing here; routing memfd_secret into
        // memfd_create made `memfd_secret(O_CLOEXEC)` an undefined MFD bit.
        assert_ne!(O_CLOEXEC, 1);
    }

    #[test]
    fn the_direct_map_capability_gates_everything_else() {
        // Documented state of THIS kernel: the HHDM is 1 GiB blocks, so a
        // secretmem page cannot be removed from the linear map and the
        // syscall must not claim otherwise. If a later change makes the
        // linear map page-granular this assertion is the thing that flips.
        assert!(!can_set_direct_map());
        assert_eq!(HHDM_LEAF_BYTES, 1 << 30);
        // ENOSYS outranks a bad flag, exactly as `mm/secretmem.c:229` runs
        // before `:232`.
        assert_eq!(memfd_secret_check(0), Err(Errno::Enosys));
        assert_eq!(memfd_secret_check(0xdead_beef), Err(Errno::Enosys));
    }

    #[test]
    fn flag_ladder_once_the_direct_map_supports_it() {
        // The ladder itself, exercised independently of the gate above.
        fn check(flags: u32) -> Result<bool, Errno> {
            let cloexec = O_CLOEXEC;
            if flags & !(SECRETMEM_FLAGS_MASK | cloexec) != 0 { return Err(Errno::Einval); }
            Ok(flags & cloexec != 0)
        }
        assert_eq!(check(0), Ok(false));
        assert_eq!(check(O_CLOEXEC), Ok(true));
        assert_eq!(check(1), Err(Errno::Einval), "MFD_CLOEXEC is not a memfd_secret flag");
        assert_eq!(check(O_CLOEXEC | 2), Err(Errno::Einval));
    }
}
