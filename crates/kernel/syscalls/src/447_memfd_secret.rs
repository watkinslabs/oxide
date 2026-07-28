// 447 memfd_secret — `SYSCALL_DEFINE1(memfd_secret)` (`mm/secretmem.c:224`).
// ABI shim (docs/53); the ladder is `crate::secretmem` (hosted-tested).
//
// Previously this slot did not exist: `route_b.rs` rewrote the arguments and
// called `sys_memfd_create(name = NULL, flags)`, which meant
// `memfd_secret(0)` returned EFAULT (memfd_create's NULL-name check) and
// `memfd_secret(O_CLOEXEC)` returned EINVAL (0x80000 is not an MFD_* bit) —
// and, had either succeeded, the caller would have received an ordinary
// shmem memfd whose pages stay in the kernel's linear map.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::SyscallArgs;

use crate::secretmem::{can_set_direct_map, memfd_secret_check};

// Compile-time barrier. This shim is only honest while single pages cannot be
// removed from the linear map. The day `hal::pt_walker` grows a huge-leaf
// split and the HHDM becomes page-granular, this breaks the BUILD instead of
// silently shipping a memfd_secret whose pages are not secret — at which
// point the work is: a `secretmem` pseudo-inode with `.release` +
// `.mmap_prepare` and no read/write op (so read(2)/write(2) are EINVAL),
// MAP_SHARED-only mmap setting VM_LOCKED|VM_DONTDUMP, a fault path that
// zeroes a fresh frame and unmaps it from the HHDM, a free path that restores
// the HHDM entry and re-zeroes, `.migrate_folio = -EBUSY`, refusal from
// gup/mlock, and `setattr` accepting ATTR_SIZE only while i_size == 0.
const _: () = assert!(!can_set_direct_map());

/// `memfd_secret(flags)` — slot 447.
/// # C: O(1)
pub fn sys_memfd_secret(args: &SyscallArgs) -> i64 {
    // Linux declares `unsigned int flags`.
    match memfd_secret_check(args.a0 as u32) {
        // Unreachable while the const assertion above holds.
        Ok(_cloexec) => -(Errno::Enosys.as_i32() as i64),
        Err(e) => -(e.as_i32() as i64),
    }
}
