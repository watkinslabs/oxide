// 461 lsm_list_modules — one syscall, one file (docs/53 §0).
//
// ABI shim only: the id list, the byte-count arithmetic and the E2BIG rule
// live in `crate::lsm` (ungated, host-tested); this file performs the two user
// copies in the order `security/lsm_syscalls.c:105-129` performs them.
//
// That order is not obvious: Linux reads `*size`, then WRITES the required
// size back, and only then decides E2BIG. A caller probing with `size = 0`
// must come back with `*size` set AND -E2BIG — writing the size after the
// check, or skipping the write when the buffer is short, breaks the
// probe-then-allocate loop every user of this syscall runs.

use syscall::{errno::Errno, SyscallArgs};

use crate::lsm::{list_modules_fits, list_modules_precheck, list_modules_total_size,
    ACTIVE_LSM_IDS, LSM_ID_BYTES};

/// # C: O(1)
fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_lsm_list_modules(ids, size, flags)` — slot 461. Returns the count of
/// active modules (`lsm_active_cnt`), not a byte count.
/// # C: O(N_lsm)
pub fn sys_lsm_list_modules(args: &SyscallArgs) -> i64 {
    let (ids_ptr, size_ptr, flags) = (args.a0, args.a1, args.a2 as u32);
    if let Err(e) = list_modules_precheck(flags) { return errno(e); }
    // `get_user(usize, size)` — a NULL or unmapped `size` is EFAULT, never a
    // silently-skipped write.
    let mut have = [0u8; 4];
    if uaccess::copy_from_user(&mut have, size_ptr).is_err() { return errno(Errno::Efault); }
    let usize_bytes = u32::from_ne_bytes(have);
    let total = list_modules_total_size();
    // `put_user(total_size, size)` — before the E2BIG decision.
    if uaccess::copy_to_user(size_ptr, &total.to_ne_bytes()).is_err() {
        return errno(Errno::Efault);
    }
    if let Err(e) = list_modules_fits(usize_bytes) { return errno(e); }
    let mut slot = ids_ptr;
    for id in ACTIVE_LSM_IDS {
        if uaccess::copy_to_user(slot, &id.to_ne_bytes()).is_err() {
            return errno(Errno::Efault);
        }
        slot = match slot.checked_add(LSM_ID_BYTES as u64) {
            Some(next) => next,
            None => return errno(Errno::Efault),
        };
    }
    ACTIVE_LSM_IDS.len() as i64
}
