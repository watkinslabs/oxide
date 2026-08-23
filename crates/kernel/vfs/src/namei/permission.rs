use crate::inode::InodeRef;
use crate::posix_acl::{self, AclType};
use crate::types::S_IRWXG;
use crate::types::{FileType, KResult, VfsError};

use super::{Cred, MAY_EXEC, MAY_READ, MAY_WRITE};

/// `generic_permission` for the access `mask`.
/// Owner/group/other class selection uses the caller credential snapshot.
/// # C: O(ngroups)
pub fn generic_permission(inode: &crate::inode::Inode, mask: u32, cred: &Cred) -> KResult<()> {
    let Some(mode) = inode.perm() else { return Ok(()); };
    let mode = mode as u32;
    let uid = inode.uid().unwrap_or(0);
    let gid = inode.gid().unwrap_or(0);
    let want = mask & (MAY_READ | MAY_WRITE | MAY_EXEC);
    let granted = if cred.uid == uid {
        (mode >> 6) & 0o7
    } else {
        // POSIX ACL (`acl_permission_check` → `check_acl`): a non-owner caller
        // is decided by the access ACL when the object carries one. The ACL
        // covers named users/groups + a mask + `other`, so it fully replaces the
        // group/other mode-bit selection. Absent an ACL, fall to the mode bits.
        // A denial still falls through to the capability rungs below, which is
        // the one reason this is not a plain early return.
        match check_acl(inode, cred, uid, gid, want, mode) {
            Some(Ok(()))                => return Ok(()),
            Some(Err(VfsError::Eacces)) => 0,
            Some(Err(e))                => return Err(e),
            None if cred.in_group(gid)  => (mode >> 3) & 0o7,
            None                        => mode & 0o7,
        }
    };
    if granted & mask == mask { return Ok(()); }
    let is_dir = matches!(inode.file_type(), FileType::Directory);
    // CAP_DAC_OVERRIDE: dirs always; non-dir exec only if some exec bit set.
    if cred.cap_dac_override
        && (is_dir || mask & MAY_EXEC == 0 || (mode & 0o111) != 0) {
        return Ok(());
    }
    // CAP_DAC_READ_SEARCH: read + directory search (not write).
    if cred.cap_dac_read_search && mask & MAY_WRITE == 0 && (is_dir || mask & MAY_EXEC == 0) {
        return Ok(());
    }
    #[cfg(feature = "debug-eacces")]
    {
        // [EACCES] DAC denial: inode identity + owner/mode vs caller creds +
        // requested access mask (r=4/w=2/x=1). Correlate with the [OPENAT] path
        // line logged for the same syscall to pin the exact file + why.
        klog::write_raw(b"[EACCES] ino=");
        klog::write_hex_u64(inode.ino() as u64);
        klog::write_raw(b" i_uid=");
        klog::write_dec_u64(uid as u64);
        klog::write_raw(b" i_gid=");
        klog::write_dec_u64(gid as u64);
        klog::write_raw(b" mode=");
        klog::write_hex_u64((mode & 0o7777) as u64);
        klog::write_raw(b" mask=");
        klog::write_hex_u64(mask as u64);
        klog::write_raw(b" c_uid=");
        klog::write_dec_u64(cred.uid as u64);
        klog::write_raw(b" c_gid=");
        klog::write_dec_u64(cred.gid as u64);
        klog::write_raw(b" dac_ovr=");
        klog::write_dec_u64(cred.cap_dac_override as u64);
        klog::write_raw(b"\n");
    }
    Err(VfsError::Eacces)
}

/// Linux `check_acl`. `None` is its `-EAGAIN`: this object carries no ACL, so
/// the caller decides from the mode bits. `Some(Err(Eacces))` is a refusal the
/// ACL made, which the capability rungs may still override; any other error is
/// the ACL itself being unreadable and is reported as-is.
///
/// The group mode bits are the guard the reference uses before it looks: a
/// mask (or, with no mask, the GROUP_OBJ entry) is folded into them by every
/// path that writes an ACL, so all-clear group bits mean the ACL can grant
/// nothing and the fetch is pointless.
/// # C: O(N_acl_entries), one medium read per inode
fn check_acl(inode: &crate::inode::Inode, cred: &Cred, i_uid: u32, i_gid: u32,
             want: u32, mode: u32) -> Option<KResult<()>> {
    if inode.i_sb().is_some_and(|sb| !sb.is_posixacl()) { return None; }
    if mode & u32::from(S_IRWXG) == 0 { return None; }
    let acl = match inode.get_inode_acl(AclType::Access) {
        Ok(acl) => acl?,
        Err(e) => return Some(Err(e)),
    };
    Some(posix_acl::permission(&acl, cred.uid, i_uid, i_gid, want as u16,
                               |g| cred.in_group(g)).map_err(acl_error))
}

/// The ACL decision's errno as a VFS error. A malformed ACL is `EIO` — the
/// object's own permission record is corrupt.
/// # C: O(1)
fn acl_error(e: syscall::errno::Errno) -> VfsError {
    match e { syscall::errno::Errno::Eacces => VfsError::Eacces, _ => VfsError::Eio }
}

/// `inode_permission` — the VFS entry every permission
/// check routes through. Dispatches to the inode's `i_op->permission` override
/// (`Inode::permission`, default `generic_permission`), so a filesystem with
/// ACLs / custom DAC can intercept WITHOUT every call-site changing.
///
/// "Nobody gets write access to an immutable file" (Linux `inode_permission`):
/// the S_IMMUTABLE reject stands AHEAD of the DAC dispatch, so it is EPERM for
/// every caller including root — a capability grants permission, not the right
/// to ignore the flag. This is what makes `chattr +i` refuse `open(O_WRONLY)`,
/// `truncate`, and every other write-intent path from one place instead of
/// each of them re-testing the flag.
/// # C: O(ngroups)
pub fn inode_permission(inode: &InodeRef, mask: u32, cred: &Cred) -> KResult<()> {
    if mask & MAY_WRITE != 0 && inode.i_flags() & crate::inode::S_IMMUTABLE != 0 {
        return Err(VfsError::Eperm);
    }
    inode.permission(mask, cred)?;
    super::device_permission(inode.file_type(), inode.rdev(), mask)?;
    // The label-based decision is SEPARATE from the discretionary one above and
    // combined by refusing if either refuses. It runs last because a refusal it
    // reports names an object the caller was otherwise entitled to reach, which
    // is the only case worth an audit record.
    mac_permission(inode, mask)
}

/// Label-based permission over an inode, decided by whichever mandatory-access
/// module the kernel glue installed.
pub type InodeMacHook = fn(&InodeRef, u32) -> KResult<()>;

static INODE_MAC_HOOK: sync::Spinlock<Option<InodeMacHook>, sync::Inode> =
    sync::Spinlock::new(None);

/// Install the label-based inode permission check. Idempotent. # C: O(1)
///
/// A hook rather than a direct call because the module that answers needs the
/// calling task's own label, and this crate sits below the task.
pub fn set_inode_mac_hook(hook: InodeMacHook) { *INODE_MAC_HOOK.lock() = Some(hook); }

/// Label hook for a freshly materialised inode. # C: O(1)
pub type InodeCreateHook = fn(&InodeRef, &InodeRef, &str);
pub type InodeInstantiateHook = fn(&crate::dentry::Dentry, &InodeRef);
/// LSM hook for secure anonymous inode initialization. # C: O(1) + hook
pub type InodeInitSecurityAnonHook = fn(&InodeRef, &str, Option<&InodeRef>) -> KResult<()>;

static INODE_CREATE_HOOK: sync::Spinlock<Option<InodeCreateHook>, sync::Inode> =
    sync::Spinlock::new(None);
static INODE_INSTANTIATE_HOOK: sync::Spinlock<Option<InodeInstantiateHook>, sync::Inode> =
    sync::Spinlock::new(None);
static INODE_INIT_SECURITY_ANON_HOOK: sync::Spinlock<Option<InodeInitSecurityAnonHook>, sync::Inode> =
    sync::Spinlock::new(None);

/// Install the create-time inode label hook. # C: O(1)
pub fn set_inode_create_hook(hook: InodeCreateHook) { *INODE_CREATE_HOOK.lock() = Some(hook); }
/// Install the hook that labels an inode with the dentry that publishes it. # C: O(1)
pub fn set_inode_instantiated_hook(hook: InodeInstantiateHook) { *INODE_INSTANTIATE_HOOK.lock() = Some(hook); }
/// Install the secure anonymous-inode initialization hook. # C: O(1)
pub fn set_inode_init_security_anon_hook(hook: InodeInitSecurityAnonHook) {
    *INODE_INIT_SECURITY_ANON_HOOK.lock() = Some(hook);
}

/// Apply the installed create-time label decision, if any. # C: O(1)
pub fn inode_created(dir: &InodeRef, inode: &InodeRef, name: &str) {
    let hook = *INODE_CREATE_HOOK.lock();
    if let Some(label) = hook { label(dir, inode, name); }
}

/// Apply the installed hook after an operation that does not return its inode. # C: O(lookup)
pub fn notify_inode_created(dir: &InodeRef, name: &str) {
    if let Ok(inode) = dir.lookup(name) { inode_created(dir, &inode, name); }
}

/// Notify the installed LSM after a positive dentry binds an inode. # C: O(1) + hook
pub fn inode_instantiated(dentry: &crate::dentry::Dentry, inode: &InodeRef) {
    if let Some(hook) = *INODE_INSTANTIATE_HOOK.lock() { hook(dentry, inode); }
}

/// Initialize security state before a secure anonymous inode is published. # C: O(1) + hook
pub fn inode_init_security_anon(inode: &InodeRef, name: &str,
                                context_inode: Option<&InodeRef>) -> KResult<()> {
    match *INODE_INIT_SECURITY_ANON_HOOK.lock() {
        Some(hook) => hook(inode, name, context_inode),
        None => Ok(()),
    }
}

/// Ask the installed module, or allow when none is installed. # C: O(1)
fn mac_permission(inode: &InodeRef, mask: u32) -> KResult<()> {
    let hook = *INODE_MAC_HOOK.lock();
    match hook { Some(check) => check(inode, mask), None => Ok(()) }
}

/// `may_lookup` (Linux): search permission (MAY_EXEC) on a directory before
/// resolving a component within it. # C: O(1)
pub(crate) fn may_lookup(inode: &InodeRef, cred: &Cred) -> KResult<()> {
    inode_permission(inode, MAY_EXEC, cred)
}

/// The open-flag rungs `may_open` applies AFTER the access-mode DAC check.
/// Carried as decoded booleans so the arch-specific numeric `O_*` values stay
/// at the syscall boundary and cannot be mismatched here.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenIntent {
    /// Access mode is not read-only (`O_WRONLY` or `O_RDWR`).
    pub write_mode: bool,
    /// `O_APPEND` requested.
    pub append: bool,
    /// `O_TRUNC` requested.
    pub trunc: bool,
    /// `O_NOATIME` requested.
    pub noatime: bool,
}

/// `may_open`: DAC check for opening `inode` with the
/// requested read/write access. A SYMLINK final inode is `ELOOP` — it only
/// reaches `may_open` when `open(O_NOFOLLOW)` (without `O_PATH`) left the
/// trailing symlink unfollowed (Linux `may_open` `case S_IFLNK: return -ELOOP`).
/// Writing to a directory is `EISDIR`; otherwise the requested access classes
/// are checked via `inode_permission` (EACCES on deny). The EROFS-on-RO-mount
/// and O_CREAT parent checks live at the syscall layer (they need the resolved
/// mount + parent inode). A freshly O_CREAT'd file skips the ACCESS-MODE part
/// (Linux sets acc_mode=0), as does an O_PATH open.
///
/// Flag-less form: the caller has no open flags to declare (in-kernel openers,
/// `MAY_EXEC` probes). [`may_open_at`] carries the full ladder. # C: O(ngroups)
pub fn may_open(inode: &InodeRef, want_read: bool, want_write: bool, cred: &Cred) -> KResult<()> {
    may_open_at(inode, want_read, want_write, OpenIntent::default(), cred)
}

/// `may_open` with the open's flag rungs, in the order the contract fixes them:
/// the file-type verdict, then the access-mode DAC check, then the append-only
/// inode rung, then the `O_NOATIME` owner rung. The flag rungs run even when the
/// access-mode mask is empty (a just-created or `acc_mode == 0` open), because
/// they are decided by the FLAGS, not by the requested access.
/// # C: O(ngroups)
pub fn may_open_at(
    inode: &InodeRef,
    want_read: bool,
    want_write: bool,
    intent: OpenIntent,
    cred: &Cred,
) -> KResult<()> {
    let mut intent = intent;
    match inode.file_type() {
        FileType::Symlink => return Err(VfsError::Eloop),
        FileType::Directory if want_write => return Err(VfsError::Eisdir),
        // A device / FIFO / socket open acts on the driver, not on filesystem
        // data, so the truncate request is dropped before the append-only rung
        // below ever sees it.
        FileType::CharDev | FileType::BlockDev | FileType::Fifo | FileType::Socket => {
            intent.trunc = false;
        }
        _ => {}
    }
    let mut mask = 0u32;
    if want_read  { mask |= MAY_READ; }
    if want_write { mask |= MAY_WRITE; }
    if mask != 0 { inode_permission(inode, mask, cred)?; }
    // An append-only inode accepts a write-mode open ONLY in append mode, and
    // never a truncating one. The flag bounds what the description may ever do,
    // so the refusal belongs at open — a description that could not legally
    // write must not exist, rather than failing at every later write.
    if inode.i_flags() & crate::inode::S_APPEND != 0 {
        if intent.write_mode && !intent.append { return Err(VfsError::Eperm); }
        if intent.trunc { return Err(VfsError::Eperm); }
    }
    // `O_NOATIME` suppresses the access-time update for every read through this
    // description, so it is an owner-only privilege: without this rung any
    // caller could silently freeze the atime of another user's file.
    if intent.noatime && !owner_or_capable(inode, cred) { return Err(VfsError::Eperm); }
    Ok(())
}

/// `inode_owner_or_capable`: the caller's filesystem uid owns `inode`, or the
/// caller holds the file-owner capability. # C: O(1)
fn owner_or_capable(inode: &InodeRef, cred: &Cred) -> bool {
    cred.uid == inode.uid().unwrap_or(0) || cred.cap_fowner
}
