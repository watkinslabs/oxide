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

/// The caller's half of [`crate::handle_policy::acceptable::dentry_acceptable`]:
/// the mount's idmap and the caller's user-namespace id maps.
///
/// The idmap is the ANCHOR MOUNT's, because that is the mount the reopened fd
/// is attached to and therefore the one whose translation userspace will see.
/// Comparing raw `i_uid`/`i_gid` instead would answer for a different mount.
/// # C: O(1)
struct AcceptableFacts {
    idmap:   Arc<vfs::idmap::Idmap>,
    uid_map: alloc::vec::Vec<nscg::user_ns::IdMapExtent>,
    gid_map: alloc::vec::Vec<nscg::user_ns::IdMapExtent>,
}

/// Gather them, or `None` when the caller has no user namespace to test
/// against — which fails the check rather than waving it through.
/// # C: O(N_extents)
fn acceptable_facts(cur: &sched::Task, anchor: &vfs::VfsPath) -> Option<AcceptableFacts> {
    use namespace_identity::NamespaceKind;
    use nscg::user_ns::{self, IdMapKind};
    let owner = cur.namespace_owner(NamespaceKind::User)?;
    Some(AcceptableFacts {
        idmap:   vfs::mount::idmap_for(anchor.mnt_id),
        uid_map: user_ns::snapshot_map(&owner, IdMapKind::Uid).unwrap_or_default(),
        gid_map: user_ns::snapshot_map(&owner, IdMapKind::Gid).unwrap_or_default(),
    })
}

/// Is every owner from `d` up to the anchor expressible by the caller — and,
/// under `check_subtree`, is the anchor on that chain at all?
/// # C: O(depth)
fn decoded_object_acceptable(facts: &Option<AcceptableFacts>, ctx: &DecodeCtx,
                             anchor: &vfs::VfsPath, d: &Arc<vfs::dentry::Dentry>) -> bool
{
    if !ctx.check_perms && !ctx.check_subtree { return true; }
    let Some(f) = facts else { return false };
    crate::handle_policy::dentry_acceptable(ctx, &f.idmap, &anchor.dentry, d, |uid, gid| {
        nscg::user_ns::has_mapping(&f.uid_map, uid) && nscg::user_ns::has_mapping(&f.gid_map, gid)
    })
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

    // 5. Reconnect. The decoded object must come back as a dentry that reaches
    //    the filesystem root, and one the caller is allowed to have — the two
    //    are decided together because an alias the caller cannot accept is a
    //    reason to keep looking, not a reason to fail.
    let facts = acceptable_facts(cur, &anchor);
    let acceptable = |d: &Arc<vfs::dentry::Dentry>| {
        decoded_object_acceptable(&facts, &ctx, &anchor, d)
    };
    let dentry = match reconnect(&sb, &fid, &inode, &acceptable) {
        Ok(d) => d, Err(e) => return err(e),
    };

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

/// Turn a decoded inode into the dentry the reopened file will carry — Linux
/// `exportfs_decode_fh_raw`'s second half.
///
/// A DIRECTORY has exactly one dentry, so the decode must make THAT dentry
/// reach the filesystem root: the reconnect walk climbs `get_parent` until it
/// meets an ancestor already in the tree, however many levels up that is. A
/// single hop leaves every level above it disconnected, so a directory more
/// than one level below the last cached ancestor came back pathless.
///
/// A NON-directory prefers an already-acceptable alias — the object may already
/// be in the cache under one of its links — and otherwise reconnects through
/// the parent the FID carries, whose OWN dentry goes through the same upward
/// walk before the child is instantiated under it.
///
/// ESTALE covers every "the tree no longer says what the handle says" case: a
/// parent that will not decode, a child no longer named in it, an unreconnectable
/// chain, and a non-directory with neither an acceptable alias nor a parent in
/// its handle. EACCES is the caller's reach failing, never a silent downgrade to
/// a pathless alias.
/// # C: O(depth * N_entries)
fn reconnect<F>(sb: &Arc<vfs::SuperBlock>, fid: &Fid, inode: &vfs::InodeRef, acceptable: F)
    -> Result<Arc<vfs::dentry::Dentry>, Errno>
where F: Fn(&Arc<vfs::dentry::Dentry>) -> bool
{
    if inode.file_type() == vfs::FileType::Directory {
        let d = vfs::export::reconnect_path(sb, inode).ok_or(Errno::Estale)?;
        if !acceptable(&d) { return Err(Errno::Eacces); }
        return Ok(d);
    }
    let result = vfs::export::fh_alias(inode.clone());
    if let Some(a) = vfs::export::find_acceptable_alias(sb, &result, &acceptable) { return Ok(a); }
    let (pino, pgen) = fid.parent.ok_or(Errno::Estale)?;
    let parent = sb.s_op.fh_to_parent(sb, pino, pgen).ok_or(Errno::Estale)?;
    let parent_dentry = vfs::export::reconnect_path(sb, &parent).ok_or(Errno::Estale)?;
    let name = vfs::export::get_name(&parent, inode.ino()).ok_or(Errno::Estale)?;
    let d = vfs::export::reconnect_child(&parent_dentry, &name, inode).ok_or(Errno::Estale)?;
    if !acceptable(&d) { return Err(Errno::Eacces); }
    Ok(d)
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
