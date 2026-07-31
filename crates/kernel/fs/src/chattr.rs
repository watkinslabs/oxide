// `chmod(2)` / `chown(2)` family work-fns — Linux `fs/open.c` `chmod_common`
// and `chown_common`. The syscall shims own only argument fetch, `AT_*` flag
// validation, path/fd resolution, and the user-namespace id translation of the
// uid/gid ARGUMENTS; every attribute decision converges here and then in
// `vfs::notify_change_mnt`.

use vfs::{Cred, FileType, Iattr, InodeRef, KResult};
use vfs::{ATTR_CTIME, ATTR_GID, ATTR_KILL_SUID, ATTR_MODE, ATTR_UID};

/// Wall-clock stamp for the `ctime` an attribute change records (Linux
/// `current_time(inode)` reads CLOCK_REALTIME, not the monotonic counter).
/// # C: O(1)
fn wall_now_ns() -> u64 { vfs::inode_times::realtime_now_ns() }

/// `chmod_common` (Linux `fs/open.c`): `ATTR_MODE | ATTR_CTIME` through
/// `notify_change`. Only the permission bits are caller-supplied — the file
/// type half of `i_mode` is preserved (`(mode & S_IALLUGO) | (i_mode &
/// ~S_IALLUGO)`), so no chmod can retype an inode. The `ctime` bit is what
/// makes a mode change observable to `make`, `rpm -V`, and every mtime/ctime
/// consumer; without it a chmod left the inode's timestamps untouched.
/// # C: O(ngroups)
pub fn chmod_common(inode: &InodeRef, mnt_id: u64, mode: u16, cred: &Cred) -> KResult<()> {
    let now = wall_now_ns();
    let mut ia = Iattr {
        valid: ATTR_MODE | ATTR_CTIME,
        mode: mode & vfs::S_IALLUGO,
        ctime: vfs::Timespec64::from_clock_ns(now),
        ..Default::default()
    };
    vfs::notify_change_mnt(inode, mnt_id, &mut ia, cred, now)
}

/// Build the `iattr` a `chown_common` issues (Linux `fs/open.c`). Split out of
/// [`chown_common`] because it is the whole decision and needs no mount:
///
/// * `None` = the `(uid_t)-1` / `(gid_t)-1` "leave alone" sentinel, which
///   contributes no `ATTR_UID`/`ATTR_GID` — but does NOT make the call a no-op.
/// * `ATTR_CTIME` is unconditional, so even `chown(path, -1, -1)` stamps.
/// * A non-directory drops its privilege bits: `ATTR_KILL_SUID` always, and
///   `ATTR_KILL_SGID` per `setattr_should_drop_sgid` — which keeps a BARE
///   S_ISGID (no group-execute: the mandatory-locking mark) when the caller is
///   in the file's group or holds CAP_FSETID, and drops it otherwise. A blanket
///   `ATTR_KILL_SGID` here would have destroyed that mark on every chown.
/// # C: O(ngroups)
pub fn chown_iattr(idmap: &vfs::Idmap, inode: &InodeRef, uid: Option<u32>, gid: Option<u32>, cred: &Cred)
    -> Iattr
{
    let mut valid = ATTR_CTIME;
    if uid.is_some() { valid |= ATTR_UID; }
    if gid.is_some() { valid |= ATTR_GID; }
    if !matches!(inode.file_type(), FileType::Directory) {
        valid |= ATTR_KILL_SUID | vfs::setattr_should_drop_sgid(idmap, inode.as_ref(), cred);
    }
    let now = wall_now_ns();
    Iattr {
        valid,
        uid: uid.unwrap_or(0), gid: gid.unwrap_or(0),
        ctime: vfs::Timespec64::from_clock_ns(now),
        ..Default::default()
    }
}

/// `chown_common` (Linux `fs/open.c`) shared by chown/lchown/fchown/fchownat.
/// `uid`/`gid` are already-translated internal ids; `None` is the `-1`
/// leave-alone sentinel. The shim reports `EINVAL` for an id the caller's user
/// namespace does not map, exactly as `make_kuid` + `setattr_vfsuid` do, so a
/// `Some` here is always representable. # C: O(ngroups)
pub fn chown_common(inode: &InodeRef, mnt_id: u64, uid: Option<u32>, gid: Option<u32>, cred: &Cred)
    -> KResult<()>
{
    let idmap = vfs::mount::idmap_for(mnt_id);
    let mut ia = chown_iattr(&idmap, inode, uid, gid, cred);
    let now = wall_now_ns();
    vfs::notify_change_mnt(inode, mnt_id, &mut ia, cred, now)
}
