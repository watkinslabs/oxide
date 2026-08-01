// 458 listmount — one syscall, one file (`docs/53 §0`).
// listmount(req, mnt_ids, nr_mnt_ids, flags): list the unique ids of the mounts
// under `req->mnt_id` (or the caller's own root for `LSMT_ROOT`), in mount-id
// order, resuming after the cursor in `req->param`.
//
// Ancestry comes from the mount TOPOLOGY (`vfs::mount::listmount_ids`), never
// from comparing rendered path strings: bind mounts share dentries and two
// unrelated mounts can render the same prefix, so a string test both misses
// real descendants and invents fake ones.

use syscall::{errno::Errno, SyscallArgs};

use crate::statmount_abi::*;

const U64: u64 = 8;

fn neg(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_listmount(req, mnt_ids, nr_mnt_ids, flags)` — slot 458. Returns the
/// count written. # C: O(N_ns × depth)
pub fn sys_listmount(args: &SyscallArgs) -> i64 {
    let (req, uids, nr, flags) = (args.a0, args.a1, args.a2 as usize, args.a3 as u32);
    if flags & !LISTMOUNT_REVERSE != 0 { return neg(Errno::Einval); }
    // A namespace with more mounts than this is the caller's problem to page
    // through, not a buffer to allocate.
    if nr > LISTMOUNT_MAX_COUNT { return neg(Errno::Eoverflow); }
    if nr != 0 {
        let Some(bytes) = (nr as u64).checked_mul(U64) else { return neg(Errno::Efault); };
        if let Err(rv) = crate::statmount_target::user_writable(uids, bytes) { return rv; }
    }
    let r = match crate::statmount_target::read_req(req, false) { Ok(r) => r, Err(rv) => return rv };
    if let Err(e) = listmount_cursor_check(r.param) { return neg(e); }
    let ns = match crate::statmount_target::resolve_ns(&r, true) { Ok(ns) => ns, Err(rv) => return rv };
    let Some((root_mnt, root_d)) = crate::statmount_target::requested_root(ns) else {
        return neg(Errno::Enoent);
    };

    // `LSMT_ROOT` lists the caller's own root subtree; any other value names a
    // mount whose subtree is listed, itself excluded.
    let (orig, skip_orig) = if r.mnt_id == LSMT_ROOT { (root_mnt, false) } else {
        let Some(m) = vfs::mount::mount_by_unique_id_in_ns(r.mnt_id, ns) else {
            return neg(Errno::Enoent);
        };
        (m.mnt_id, true)
    };
    // The subtree the caller points at must itself be visible from the caller's
    // root, or the caller must administer the namespace.
    if !vfs::mount::mount_reachable_from(orig, root_mnt, &root_d)
        && !crate::statmount_target::may_admin_ns(ns) {
        return neg(Errno::Eperm);
    }
    if nr == 0 { return 0; }

    let ids = vfs::mount::listmount_ids(ns, orig, skip_orig, r.param,
                                        flags & LISTMOUNT_REVERSE != 0, nr);
    for (i, id) in ids.iter().enumerate() {
        // SAFETY: `uids` validated writable for `nr` u64 entries above and
        // `ids.len() <= nr`; the copy-out target need not be aligned.
        unsafe { core::ptr::write_unaligned((uids + i as u64 * U64) as *mut u64, *id); }
    }
    ids.len() as i64
}
