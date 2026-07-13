// 458 listmount — one syscall, one file (docs/53 §0).
// listmount(req, mnt_ids, nr_mnt_ids, flags): write mount ids reachable under
// req->mnt_id (or caller root for LSMT_ROOT) into the user array.
use syscall::{errno::Errno, SyscallArgs};
use alloc::vec::Vec;

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

const REQ_OFF_SIZE:   u64 = 0;
const REQ_OFF_MNT_ID: u64 = 8;
const REQ_OFF_PARAM:  u64 = 16;
const REQ_MIN_SIZE:   u64 = 24;
const REQ_MAX_SIZE:   u64 = 4096;
const LSMT_ROOT:      u64 = u64::MAX;   // list the namespace root mount(s)
const LISTMOUNT_REVERSE: u64 = 1;
const U64:            u64 = 8;

fn read_req(req: u64) -> Result<(u64, u64), i64> {
    if let Err(rv) = validate_user_buf(req, 4, 1) { return Err(rv); }
    // SAFETY: req validated readable for the size prefix.
    let size = unsafe { core::ptr::read_unaligned((req + REQ_OFF_SIZE) as *const u32) } as u64;
    if size < REQ_MIN_SIZE { return Err(-(Errno::Einval.as_i32() as i64)); }
    if size > REQ_MAX_SIZE { return Err(-(Errno::E2big.as_i32() as i64)); }
    if let Err(rv) = validate_user_buf(req, size, 1) { return Err(rv); }
    // SAFETY: req validated readable for the minimum mnt_id_req fields.
    let target = unsafe { core::ptr::read_unaligned((req + REQ_OFF_MNT_ID) as *const u64) };
    // SAFETY: req validated readable for the minimum mnt_id_req fields.
    let after = unsafe { core::ptr::read_unaligned((req + REQ_OFF_PARAM) as *const u64) };
    Ok((target, after))
}

fn under_root(path: &str, root: &str) -> bool {
    if root == "/" { return path.starts_with('/'); }
    path == root || path.strip_prefix(root).map(|rest| rest.starts_with('/')).unwrap_or(false)
}

#[cfg(feature = "debug-mount")]
fn trace_listmount(ns: u64, target: u64, after: u64, flags: u64, rv: i64) {
    klog::write_raw(b"[MOUNTAPI] listmount ns="); klog::write_dec_u64(ns);
    klog::write_raw(b" target="); klog::write_dec_u64(target);
    klog::write_raw(b" after="); klog::write_dec_u64(after);
    klog::write_raw(b" flags="); klog::write_dec_u64(flags);
    klog::write_raw(b" rv=");
    if rv < 0 { klog::write_raw(b"-"); klog::write_dec_u64((-rv) as u64); }
    else { klog::write_dec_u64(rv as u64); }
    klog::write_raw(b"\n");
}

/// `sys_listmount(req, mnt_ids, nr_mnt_ids, flags)` — slot 458.
/// Returns the count written.
/// # C: O(N_mounts)
pub fn sys_listmount(args: &SyscallArgs) -> i64 {
    let req  = args.a0;
    let uids = args.a1;
    let nr   = args.a2 as usize;
    let flags = args.a3;
    if flags & !LISTMOUNT_REVERSE != 0 { return -(Errno::Einval.as_i32() as i64); }
    let (target, after) = match read_req(req) { Ok(v) => v, Err(rv) => return rv };
    let ns = ::vfs::mount::current_ns();
    let mounts = ::vfs::mount::snapshot_ns_view(ns);
    let root_path = if target == LSMT_ROOT {
        alloc::string::String::from("/")
    } else {
        let Some(root) = ::vfs::mount::mount_by_id(target) else {
            return -(Errno::Enoent.as_i32() as i64);
        };
        if root.ns != ns { return -(Errno::Enoent.as_i32() as i64); }
        root.mount_point_str()
    };
    let mut ids: Vec<u64> = Vec::new();
    for m in &mounts {
        if target != LSMT_ROOT && m.mnt_id == target { continue; }
        if after != 0 && m.mnt_id <= after { continue; }
        if under_root(&m.mount_point_str(), &root_path) { ids.push(m.mnt_id); }
    }
    if flags & LISTMOUNT_REVERSE != 0 { ids.reverse(); }
    if nr == 0 { return 0; }
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
    let rv = n as i64;
    #[cfg(feature = "debug-mount")]
    trace_listmount(ns, target, after, flags, rv);
    rv
}
