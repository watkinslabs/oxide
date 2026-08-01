// open_by_handle_at(2) per `15§5` / `16` — the reverse of name_to_handle_at.
// Reopens a file from the handle 303 emitted, with NO path walk: `mountdirfd`
// identifies the filesystem (its superblock), the FID supplies
// `(ino, generation)`, and `s_export_op->fh_to_dentry` turns that back into an
// inode — re-reading it from the backing store when it is no longer cached,
// which is what makes a handle outlive the last opener.
//
// ORDER follows Linux `handle_to_path`: the handle header is validated FIRST
// (EINVAL), then the mount fd is resolved (EBADF), and only then is
// `may_decode_fh` consulted (EPERM). Checking the capability first told an
// unprivileged caller "permission denied" for a malformed handle or a closed fd
// — two errors privilege would never have fixed.
//
// Header/flag/FID/permission decisions live in `crate::handle_policy`
// (hosted-tested); this file is the shim (docs/53).

#![cfg(target_os = "oxide-kernel")]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{File, OpenFlags};

use crate::handle_policy::{DecodeCtx, FILEID_IS_CONNECTABLE, FILEID_IS_DIR, Fid, HANDLE_HDR,
    MayDecodeFh, decode::O_DIRECTORY, decode_fid, handle_header_check, header_is_our_fid,
    may_decode_fh, strip_user_flags};
use crate::userbuf::validate_user_buf;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Gather the facts `may_decode_fh` weighs, from the task, the anchor's mount
/// and the anchor's superblock. Kept beside the ladder's only caller: the
/// DECISION is hosted-tested in `handle_policy::decode`, this is the lookup.
/// # C: O(depth of user-ns chain + children of the anchor mount)
fn may_decode_facts(cur: &sched::Task, anchor: &vfs::VfsPath, o_flags: u32) -> MayDecodeFh {
    use namespace_identity::NamespaceKind;
    // `capable(X)` is `ns_capable(&init_user_ns, X)`: the capability held over
    // the INITIAL user namespace, not merely inside the caller's own. Reducing
    // it to the effective-set test would hand every user-namespace root the
    // unrestricted decode path.
    let init_user_ns = namespace_identity::initial(NamespaceKind::User).pin();
    let cap_dac_read_search = nscg::proc_ns::has_cap_for(cur, &init_user_ns,
                                                         sched::cap::DAC_READ_SEARCH);
    let sb = anchor.inode.i_sb();
    let sys_admin_over_sb_userns = sb.as_ref().is_some_and(|sb|
        nscg::proc_ns::has_cap_for(cur, &sb.s_user_ns, sched::cap::SYS_ADMIN));
    let mount = vfs::mount::mount_by_id(anchor.mnt_id);
    // Linux `is_mounted(mnt)`: the mount is still attached to a namespace. A
    // detached mount cannot be bind-mounted, so the bind argument fails.
    let anchor_is_mounted = mount.as_ref().is_some_and(|m| !m.is_detached());
    let sys_admin_over_mnt_ns = mount.as_ref()
        .and_then(|m| vfs::mntns::ns_by_id(m.namespace_id()))
        .is_some_and(|ns| nscg::proc_ns::has_cap_for(cur, &ns.owner_user_namespace(),
                                                     sched::cap::SYS_ADMIN));
    let has_locked_children = mount.as_ref()
        .is_some_and(|m| vfs::mount::has_locked_children(m, &anchor.dentry));
    // `ns_capable(current_user_ns(), CAP_DAC_READ_SEARCH)`.
    let dac_read_search_in_user_ns = cur.namespace_owner(NamespaceKind::User)
        .is_some_and(|ns| nscg::proc_ns::has_cap_for(cur, &ns.pin(),
                                                     sched::cap::DAC_READ_SEARCH));
    MayDecodeFh {
        cap_dac_read_search,
        o_directory: o_flags & O_DIRECTORY != 0,
        sys_admin_over_sb_userns,
        anchor_is_mounted,
        sys_admin_over_mnt_ns,
        has_locked_children,
        dac_read_search_in_user_ns,
    }
}

/// Is every uid/gid from `inode` up to the anchor mapped in the caller's user
/// namespace? Linux `vfs_dentry_acceptable`: the relaxed decode path may
/// override DAC, but it must not reach an object whose owner it cannot even
/// express — that would be reach the caller could not have obtained by walking.
///
/// Also answers containment for `check_subtree`: the walk terminates at the
/// anchor, so "reached the anchor" and "is inside the anchor's subtree" are the
/// same answer and cannot disagree.
/// # C: O(depth)
fn decoded_object_acceptable(cur: &sched::Task, ctx: &DecodeCtx, anchor: &vfs::VfsPath,
                             d: &Arc<vfs::dentry::Dentry>) -> bool
{
    if !ctx.check_perms && !ctx.check_subtree { return true; }
    use namespace_identity::NamespaceKind;
    use nscg::user_ns::{self, IdMapKind};
    let owner = match cur.namespace_owner(NamespaceKind::User) { Some(o) => o, None => return false };
    let uid_map = user_ns::snapshot_map(&owner, IdMapKind::Uid).unwrap_or_default();
    let gid_map = user_ns::snapshot_map(&owner, IdMapKind::Gid).unwrap_or_default();
    // An inode with no owner to report cannot be shown to be reachable, so it
    // fails the check rather than being waved through.
    let mapped = |i: &vfs::InodeRef| match (i.uid(), i.gid()) {
        (Some(u), Some(g)) => user_ns::has_mapping(&uid_map, u) && user_ns::has_mapping(&gid_map, g),
        _                  => false,
    };
    let mut cur_d = d.clone();
    loop {
        // The ownership leg is skipped for a caller holding the global
        // capability; the containment leg still runs, because a CONNECTABLE
        // handle is confined to the anchor's subtree whoever presents it.
        if ctx.check_perms {
            match cur_d.inode() { Some(i) if mapped(&i) => {}, _ => return false }
        }
        if Arc::ptr_eq(&cur_d, &anchor.dentry) { return true; }
        match cur_d.parent() {
            Some(p) => cur_d = p.clone(),
            // Reached a filesystem root without meeting the anchor. Acceptable
            // only when containment was not required.
            None    => return !ctx.check_subtree,
        }
    }
}

/// `sys_open_by_handle_at(mountdirfd, file_handle, flags)` — slot 304.
/// Errors: EINVAL (malformed handle header), EBADF (bad `mountdirfd`), EPERM
/// (`may_decode_fh` refused), ESTALE (handle from a foreign encoder, an inode
/// that is gone, a generation mismatch, or a connectable handle whose child is
/// no longer in the named parent), ENOTDIR (a directory-only decode resolved a
/// non-directory), EACCES (the decoded object failed the ownership/containment
/// re-check the relaxed decode path imposes).
/// # C: O(log N_ino), O(N_entries) for a connectable non-directory
pub fn sys_open_by_handle_at(args: &SyscallArgs) -> i64 {
    let mountdirfd = args.a0 as i32;
    let handle_ptr = args.a1;
    let flags = args.a2 as u32;

    // 1. Handle header — the EINVAL ladder, before any fd lookup or capability
    //    check.
    if let Err(rv) = validate_user_buf(handle_ptr, HANDLE_HDR, 1) { return rv; }
    // SAFETY: handle_ptr validated readable for the 8-byte header in the caller's AS by validate_user_buf; unaligned reads of handle_bytes(u32) then handle_type(i32).
    let (bytes, raw_htype) = unsafe {
        (core::ptr::read_unaligned(handle_ptr as *const u32),
         core::ptr::read_unaligned((handle_ptr + 4) as *const i32))
    };
    if let Err(e) = handle_header_check(bytes, raw_htype) { return err(e); }

    // 2. Anchor — `get_path_anchor(mountdirfd)`. AT_FDCWD is a valid anchor
    //    (the cwd's mount), not a bad fd; the empty-path resolver is the one
    //    place that mapping lives.
    let anchor = match crate::pathresolve::resolve_at_lookup_maybe_null(
        mountdirfd, 0, vfs::LookupFlags { empty: true, ..Default::default() })
    {
        Ok(p)  => p,
        Err(_) => return err(Errno::Ebadf),
    };

    // 3. `may_decode_fh` — the handle sidesteps path-walk permission, so this
    //    ladder replaces it, and hands back what the decode must re-verify.
    let cur = match sched::live::current() { Some(c) => c, None => return err(Errno::Ebadf) };
    let mut ctx = match may_decode_fh(may_decode_facts(cur, &anchor, flags)) {
        Ok(c)  => c,
        Err(e) => return err(e),
    };
    // The handle's own user flags add obligations on top of the caller's:
    // a connectable handle must land inside the anchor's subtree, and a handle
    // that claims to name a directory must decode to one.
    if raw_htype & FILEID_IS_CONNECTABLE != 0 { ctx.check_subtree = true; }
    if raw_htype & FILEID_IS_DIR != 0 { ctx.dir_only = true; }

    // 4. Decode. A well-formed handle from a different encoder is not EINVAL:
    //    an undecodable-but-valid handle is ESTALE, because it may simply
    //    describe an object this filesystem no longer has.
    if !header_is_our_fid(bytes, raw_htype) { return err(Errno::Estale); }
    if let Err(rv) = validate_user_buf(handle_ptr + HANDLE_HDR, bytes as u64, 1) { return rv; }
    let mut fid_bytes = vec![0u8; bytes as usize];
    for (i, b) in fid_bytes.iter_mut().enumerate() {
        // SAFETY: f_handle region validated readable for `bytes` in the caller's AS above; byte-wise unaligned reads of the little-endian FID payload.
        *b = unsafe { core::ptr::read_unaligned((handle_ptr + HANDLE_HDR + i as u64) as *const u8) };
    }
    let fid = match decode_fid(&fid_bytes, strip_user_flags(raw_htype)) {
        Ok(f) => f, Err(e) => return err(e),
    };

    let sb = match anchor.inode.i_sb() { Some(s) => s, None => return err(Errno::Estale) };
    let inode = match sb.s_op.fh_to_dentry(&sb, fid.ino, fid.generation) {
        Some(i) => i, None => return err(Errno::Estale),
    };
    if ctx.dir_only && inode.file_type() != vfs::FileType::Directory {
        return err(Errno::Enotdir);
    }

    // 5. Reconnect. A connectable non-directory handle carries its parent, so
    //    the decoded object gets a real `(parent, name)` dentry rather than an
    //    anonymous alias with no renderable path. Everything else takes the
    //    alias — for a directory that IS the connected dentry, since a
    //    directory has exactly one.
    let dentry = match reconnect(&sb, &fid, &inode) { Ok(d) => d, Err(e) => return err(e) };

    if !decoded_object_acceptable(cur, &ctx, &anchor, &dentry) { return err(Errno::Eacces); }

    // DAC + EROFS enforcement against the requested access mode
    // (`do_handle_open` -> `vfs_open` -> `may_open`), through the mount the
    // handle was decoded on.
    let mnt_id = anchor.mnt_id;
    if let Some(rv) = crate::open_common::enforce_open_perm(&inode, mnt_id, flags, false) {
        return rv;
    }
    let oflags = OpenFlags::from_bits_truncate(flags) - OpenFlags::O_CLOEXEC;
    let file_cred = match crate::pathresolve::file_cred_for(cur) {
        Some(cred) => cred, None => return err(Errno::Esrch),
    };
    let file = File::new_at(inode, dentry, oflags, mnt_id, file_cred);
    if let Err(e) = file.open_hook() { return -(e as i64); }
    match fdt_alloc(cur, file, flags) { Ok(fd) => fd, Err(rv) => rv }
}

/// Turn a decoded inode into the dentry the reopened file will carry.
///
/// With a parent in the FID this is Linux's `fh_to_parent` →
/// `exportfs_get_name` → `lookup_one` sequence: resolve the parent, scan it for
/// the entry naming this inode, and instantiate that `(parent, name)` cache
/// node. A child that is no longer an entry of that parent (unlinked, or
/// renamed away since the handle was minted) is ESTALE — never a silent
/// downgrade to a disconnected alias, which would report success while handing
/// back an fd whose path cannot be rendered.
/// # C: O(N_entries) with a parent, else O(N_aliases)
fn reconnect(sb: &Arc<vfs::SuperBlock>, fid: &Fid, inode: &vfs::InodeRef)
    -> Result<Arc<vfs::dentry::Dentry>, Errno>
{
    let Some((pino, pgen)) = fid.parent else { return Ok(vfs::export::fh_alias(inode.clone())); };
    let parent = sb.s_op.fh_to_parent(sb, pino, pgen).ok_or(Errno::Estale)?;
    let name = vfs::export::get_name(&parent, inode.ino()).ok_or(Errno::Estale)?;
    let parent_dentry = vfs::export::fh_alias(parent);
    vfs::export::reconnect_child(&parent_dentry, &name, inode).ok_or(Errno::Estale)
}

/// Install the reopened file under the RLIMIT_NOFILE soft cap, honoring
/// O_CLOEXEC. # C: O(1)
fn fdt_alloc(cur: &sched::Task, file: alloc::sync::Arc<File>, flags: u32) -> Result<i64, i64> {
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; Arc clone.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return Err(err(Errno::Ebadf)),
    };
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if (flags & OpenFlags::O_CLOEXEC.bits()) != 0 {
                if let Err(e) = fdt.set_cloexec(fd, true) { return Err(-(e as i64)); }
            }
            Ok(fd as i64)
        }
        Err(e) => Err(-(e as i64)),
    }
}
