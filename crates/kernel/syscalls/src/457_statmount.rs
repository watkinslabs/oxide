// 457 statmount — one syscall, one file (`docs/53 §0`).
// statmount(req, buf, bufsize, flags): report the requested fields of one
// mount. Parse / validate / fetch / call-one-work-fn / encode only — the field
// mask, the request struct and the output layout belong to `statmount_abi`, the
// mount facts to `vfs::mount::statmount_facts`, and the namespace/root sampling
// to `statmount_target`.
use alloc::string::String;
use alloc::vec::Vec;
use syscall::{errno::Errno, SyscallArgs};

use crate::statmount_abi::*;

fn neg(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Translate one mount id-map extent into the caller's user namespace, or
/// `None` when the whole range does not resolve there — a row the caller could
/// not name is omitted rather than reported with an id that means nothing to
/// it. # C: O(extents)
fn row_in_caller_ns(e: &vfs::idmap::IdExtent, kind: nscg::user_ns::IdMapKind)
                    -> Option<IdMapRow> {
    let owner = crate::statmount_target::current_user_ns()?;
    let map = nscg::user_ns::snapshot_map(&owner, kind).ok()?;
    let last = e.fs_lo.checked_add(e.count.checked_sub(1)?)?;
    let lo = nscg::user_ns::to_ns_checked(&map, e.fs_lo)?;
    let hi = nscg::user_ns::to_ns_checked(&map, last)?;
    if hi.checked_sub(lo) != e.count.checked_sub(1) { return None; }
    Some((e.vfs_lo, lo, e.count))
}

fn rows(ext: &[vfs::idmap::IdExtent], kind: nscg::user_ns::IdMapKind) -> Vec<IdMapRow> {
    ext.iter().filter_map(|e| row_in_caller_ns(e, kind)).collect()
}

/// Split a `show_options` tail into the individual options `STATMOUNT_OPT_ARRAY`
/// reports one per element. # C: O(len)
fn split_opts(opts: &str) -> Vec<String> {
    if opts.is_empty() { return Vec::new(); }
    opts.split(',').map(String::from).collect()
}

fn record_from(f: &vfs::mount::MountFacts) -> StatmountRecord {
    StatmountRecord {
        mnt_id: f.mnt_id, mnt_parent_id: f.mnt_parent_id,
        mnt_id_old: f.mnt_id_old, mnt_parent_id_old: f.mnt_parent_id_old,
        mnt_attr: f.mnt_attr, mnt_propagation: f.mnt_propagation,
        mnt_peer_group: f.mnt_peer_group, mnt_master: f.mnt_master,
        propagate_from: f.propagate_from,
        sb_dev_major: f.sb_dev_major, sb_dev_minor: f.sb_dev_minor,
        sb_magic: f.sb_magic, sb_flags: f.sb_flags,
        mnt_ns_id: f.mnt_ns_id,
        fs_type: f.fs_type.clone(), mnt_root: f.mnt_root.clone(),
        mnt_point: f.mnt_point.clone(),
        mnt_opts: f.mnt_opts.clone(), sb_source: f.sb_source.clone(),
        fs_subtype: f.fs_subtype.clone(),
        opt_array: split_opts(&f.mnt_opts),
        // No security module in this tree publishes superblock options, so the
        // security option array is empty and its field stays absent.
        opt_sec_array: Vec::new(),
        idmapped: f.idmapped,
        uid_map: rows(&f.uid_extents, nscg::user_ns::IdMapKind::Uid),
        gid_map: rows(&f.gid_extents, nscg::user_ns::IdMapKind::Gid),
    }
}

/// `sys_statmount(req, buf, bufsize, flags)` — slot 457.
/// # C: O(N_ns + selected fields)
pub fn sys_statmount(args: &SyscallArgs) -> i64 {
    let (req, ubuf, bufsize, flags) = (args.a0, args.a1, args.a2 as usize, args.a3 as u32);
    if flags & !STATMOUNT_BY_FD != 0 { return neg(Errno::Einval); }
    let by_fd = flags & STATMOUNT_BY_FD != 0;
    let r = match crate::statmount_target::read_req(req, by_fd) { Ok(r) => r, Err(rv) => return rv };

    let (mnt_id, ns) = if by_fd {
        let id = match crate::statmount_target::mount_of_fd(r.fd) { Ok(id) => id, Err(rv) => return rv };
        let Some(m) = vfs::mount::mount_by_id(id) else { return neg(Errno::Enoent); };
        (id, m.namespace_id())
    } else {
        let ns = match crate::statmount_target::resolve_ns(&r, false) {
            Ok(ns) => ns, Err(rv) => return rv,
        };
        let Some(m) = vfs::mount::mount_by_unique_id_in_ns(r.mnt_id, ns) else {
            return neg(Errno::Enoent);
        };
        (m.mnt_id, ns)
    };
    let Some((root_mnt, root_d)) = crate::statmount_target::requested_root(ns) else {
        return neg(Errno::Enoent);
    };

    let mut want = r.param & STATMOUNT_SUPPORTED;
    // A mount outside the caller's root is invisible unless the caller
    // administers the namespace that owns it. A descriptor-named mount skips
    // this: holding the fd is already the authority.
    if !by_fd && !vfs::mount::mount_reachable_from(mnt_id, root_mnt, &root_d)
        && !crate::statmount_target::may_admin_ns(ns) {
        return neg(Errno::Eperm);
    }
    let Some(facts) = vfs::mount::statmount_facts(mnt_id, root_mnt, &root_d) else {
        return neg(Errno::Enoent);
    };
    // A detached mount has no position and no namespace, so neither its mount
    // point nor its namespace id can be reported — the fields are dropped from
    // the reply mask rather than filled with a stale answer.
    if facts.mnt_point.is_none() { want &= !STATMOUNT_MNT_POINT; }
    let out = match encode_statmount(&record_from(&facts), want, bufsize) {
        Ok(out) => out, Err(e) => return neg(e),
    };
    if let Err(rv) = crate::statmount_target::user_writable(ubuf, out.len() as u64) { return rv; }
    // SAFETY: `ubuf` validated writable for `out.len()` bytes, which the encoder
    // capped against `bufsize`; a byte copy is alignment-independent.
    unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), ubuf as *mut u8, out.len()); }
    0
}
