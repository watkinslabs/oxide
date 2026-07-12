// 458 listmount — one syscall, one file (docs/53 §0).
// listmount(req, mnt_ids, nr_mnt_ids, flags): write the child mount ids of
// req->mnt_id (or the namespace root mounts for LSMT_ROOT) into the user array.
use syscall::{errno::Errno, SyscallArgs};
use alloc::vec::Vec;

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

const REQ_OFF_MNT_ID: u64 = 8;
const REQ_MIN_SIZE:   u64 = 24;
const LSMT_ROOT:      u64 = u64::MAX;   // list the namespace root mount(s)
const U64:            u64 = 8;

/// `sys_listmount(req, mnt_ids, nr_mnt_ids, flags)` — slot 458.
/// Returns the count written (with nr_mnt_ids==0, the total available).
/// # C: O(N_mounts^2) — parent derivation per mount
pub fn sys_listmount(args: &SyscallArgs) -> i64 {
    let req  = args.a0;
    let uids = args.a1;
    let nr   = args.a2 as usize;
    if let Err(rv) = validate_user_buf(req, REQ_MIN_SIZE, 1) { return rv; }
    // SAFETY: req validated readable for the minimum mnt_id_req prefix.
    let target = unsafe { core::ptr::read_unaligned((req + REQ_OFF_MNT_ID) as *const u64) };
    let mounts = ::vfs::mount::all_mounts();
    let mut ids: Vec<u64> = Vec::new();
    for m in &mounts {
        let pid = ::vfs::mount::parent_mnt_id(m);
        let take = if target == LSMT_ROOT { pid == m.mnt_id } else { pid == target && m.mnt_id != target };
        if take { ids.push(m.mnt_id); }
    }
    if nr == 0 { return ids.len() as i64; }
    let n = ids.len().min(nr);
    if n == 0 { return 0; }
    let Some(out_len) = (n as u64).checked_mul(U64) else {
        return -(Errno::Efault.as_i32() as i64);
    };
    if let Err(rv) = validate_user_buf_writable(uids, out_len, 1) { return rv; }
    for (i, id) in ids.iter().take(n).enumerate() {
        // SAFETY: uids validated writable for n u64 entries; Linux copyout accepts unaligned storage.
        unsafe { core::ptr::write_unaligned((uids + i as u64 * U64) as *mut u64, *id); }
    }
    n as i64
}
