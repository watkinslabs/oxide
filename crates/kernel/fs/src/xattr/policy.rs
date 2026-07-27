// Linux xattr DECISION layer, with no user-buffer access and no storage, so the
// hosted `cargo test` suite drives every rule here directly:
//   * `xattr_resolve_name` (fs/xattr.c) — which namespaces have a handler.
//   * `may_write_xattr` + `xattr_permission` (fs/xattr.c) — the permission model.
//   * `cap_inode_setxattr` / `cap_inode_removexattr` / `cap_convert_nscap`
//     (security/commoncap.c) — the `security.*` capability gate.
//   * `setxattr_copy` (fs/xattr.c) — flag / name / value-size limits.
//   * the `ERANGE` vs `E2BIG` buffer arithmetic of `do_getxattr` / `listxattr`.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use vfs::{FileType, InodeRef};

/// `XATTR_CREATE` / `XATTR_REPLACE` (`uapi/linux/xattr.h`).
pub const XATTR_CREATE:  u32 = 0x1;
pub const XATTR_REPLACE: u32 = 0x2;
/// Every flag bit `setxattr_copy` accepts; anything else is `EINVAL`.
pub const XATTR_SET_FLAGS: u32 = XATTR_CREATE | XATTR_REPLACE;

/// `XATTR_NAME_MAX` / `XATTR_SIZE_MAX` / `XATTR_LIST_MAX` (`uapi/linux/limits.h`).
pub const XATTR_NAME_MAX: usize = 255;
pub const XATTR_SIZE_MAX: usize = 65536;
pub const XATTR_LIST_MAX: usize = 65536;

/// Namespace prefixes (`uapi/linux/xattr.h`).
pub const SECURITY_PREFIX: &str = "security.";
pub const SYSTEM_PREFIX:   &str = "system.";
pub const TRUSTED_PREFIX:  &str = "trusted.";
pub const USER_PREFIX:     &str = "user.";
/// `XATTR_NAME_CAPS` — the file-capability attribute, gated by CAP_SETFCAP.
pub const NAME_CAPS: &str = "security.capability";
/// The two POSIX-ACL attribute names, which bypass the generic handler stack.
pub const NAME_ACL_ACCESS:  &str = "system.posix_acl_access";
pub const NAME_ACL_DEFAULT: &str = "system.posix_acl_default";

/// `VFS_CAP_REVISION_2` / `_3` and their exact blob sizes
/// (`uapi/linux/capability.h`): `XATTR_CAPS_SZ_2` = 4*(1+2*2), `_3` = 4*(2+2*2).
const VFS_CAP_REVISION_MASK: u32 = 0xFF00_0000;
const VFS_CAP_REVISION_2:    u32 = 0x0200_0000;
const VFS_CAP_REVISION_3:    u32 = 0x0300_0000;
const XATTR_CAPS_SZ_2: usize = 20;
const XATTR_CAPS_SZ_3: usize = 24;

/// Negative-errno syscall return for `e`. # C: O(1)
pub fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The credential slice the xattr rules consult: the VFS DAC snapshot plus the
/// two capabilities `vfs::Cred` does not carry (CAP_SYS_ADMIN gates
/// `trusted.*`/`security.*`, CAP_SETFCAP gates `security.capability`).
/// # C: O(1)
pub struct XattrCred {
    pub cred: vfs::Cred,
    pub sys_admin: bool,
    pub setfcap: bool,
}

impl XattrCred {
    /// Fully privileged (early boot has no task; Linux boots as root). # C: O(1)
    pub fn root() -> Self { Self { cred: vfs::Cred::root(), sys_admin: true, setfcap: true } }

    /// `inode_owner_or_capable` (Linux `fs/inode.c`). # C: O(1)
    pub fn owns(&self, inode: &InodeRef) -> bool {
        self.cred.cap_fowner || self.cred.uid == inode.uid().unwrap_or(0)
    }
}

/// `current_cred()` widened with the two xattr-relevant capability bits.
/// # C: O(1)
pub fn current_xattr_cred() -> XattrCred {
    let Some(c) = sched::current() else { return XattrCred::root(); };
    let effective = c.creds.cap_effective.load(Ordering::Acquire);
    XattrCred {
        cred: c.creds.to_vfs_cred(c.creds.fsuid.load(Ordering::Acquire),
                                  c.creds.fsgid.load(Ordering::Acquire), effective),
        sys_admin: c.has_cap(sched::cap::SYS_ADMIN),
        setfcap:   c.has_cap(sched::cap::SETFCAP),
    }
}

/// `xattr_permission_error` — a denied WRITE is `EPERM`, a denied READ hides the
/// attribute's existence with `ENODATA`. # C: O(1)
fn permission_error(mask: u32) -> i64 {
    if mask & vfs::MAY_WRITE != 0 { err(Errno::Eperm) } else { err(Errno::Enodata) }
}

/// `may_write_xattr` — no xattr write to an immutable or append-only inode.
/// The read-only-mount half is the caller's `mnt_want_write`. # C: O(1)
pub fn may_write_xattr(inode: &InodeRef) -> Result<(), i64> {
    if inode.i_flags() & (vfs::S_IMMUTABLE | vfs::S_APPEND) != 0 { return Err(err(Errno::Eperm)); }
    Ok(())
}

/// `xattr_permission`. `security.*`/`system.*` are left entirely to the LSM +
/// filesystem handler (no DAC); `trusted.*` is CAP_SYS_ADMIN only; `user.*` is
/// restricted by file type (and by ownership on a STICKY directory) and then
/// takes the ordinary DAC check; every other namespace takes plain DAC and is
/// rejected later by [`resolve_name`]. # C: O(ngroups)
pub fn xattr_permission(inode: &InodeRef, name: &str, mask: u32, c: &XattrCred) -> Result<(), i64> {
    if mask & vfs::MAY_WRITE != 0 { may_write_xattr(inode)?; }
    if name.starts_with(SECURITY_PREFIX) || name.starts_with(SYSTEM_PREFIX) { return Ok(()); }
    if name.starts_with(TRUSTED_PREFIX) {
        if !c.sys_admin { return Err(permission_error(mask)); }
        return Ok(());
    }
    if name.starts_with(USER_PREFIX) {
        match inode.file_type() {
            // Regular files and sockets are unconditionally eligible.
            FileType::Regular | FileType::Socket => {}
            FileType::Directory => {
                let sticky = inode.perm().unwrap_or(0) & vfs::types::S_ISVTX != 0;
                if sticky && mask & vfs::MAY_WRITE != 0 && !c.owns(inode) {
                    return Err(err(Errno::Eperm));
                }
            }
            _ => return Err(permission_error(mask)),
        }
    }
    vfs::inode_permission(inode, mask, &c.cred).map_err(|e| -(e as i64))
}

/// `xattr_resolve_name` — is there a handler for this name's namespace? A bare
/// prefix with an empty suffix (`"user."`) is `EINVAL`; an unregistered
/// namespace is `EOPNOTSUPP`. The POSIX-ACL names are whole-name handlers.
/// # C: O(1)
pub fn resolve_name(name: &str) -> Result<(), i64> {
    if name == NAME_ACL_ACCESS || name == NAME_ACL_DEFAULT { return Ok(()); }
    for p in [USER_PREFIX, TRUSTED_PREFIX, SECURITY_PREFIX] {
        if let Some(rest) = name.strip_prefix(p) {
            return if rest.is_empty() { Err(err(Errno::Einval)) } else { Ok(()) };
        }
    }
    Err(err(Errno::Eopnotsupp))
}

/// `setxattr_copy` flag validation — only CREATE/REPLACE exist. Both together
/// is NOT an error here: the store reports `EEXIST`/`ENODATA` per Linux
/// `simple_xattr_set`. # C: O(1)
pub fn check_set_flags(flags: u32) -> Result<(), i64> {
    if flags & !XATTR_SET_FLAGS != 0 { return Err(err(Errno::Einval)); }
    Ok(())
}

/// `import_xattr_name` — an empty name, or one with no NUL inside
/// `XATTR_NAME_MAX + 1` bytes, is `ERANGE`. Counts RAW Linux name bytes.
/// # C: O(len)
pub fn check_name(name: &str) -> Result<(), i64> {
    let len = vfs::path_into_bytes(name).len();
    if len == 0 || len > XATTR_NAME_MAX { return Err(err(Errno::Erange)); }
    Ok(())
}

/// `setxattr_copy` value-size limit, applied BEFORE the value is copied in.
/// # C: O(1)
pub fn check_value_size(size: usize) -> Result<(), i64> {
    if size > XATTR_SIZE_MAX { return Err(err(Errno::E2big)); }
    Ok(())
}

/// `do_getxattr`/`listxattr` buffer arithmetic for a non-probe call: the user
/// size is first CAPPED at `max`, then a short buffer is `ERANGE` — except when
/// the cap itself is what made it short, which Linux reports as `E2BIG`.
/// # C: O(1)
pub fn check_fit(want: usize, size: usize, max: usize) -> Result<(), i64> {
    let cap = if size > max { max } else { size };
    if want > cap {
        return Err(err(if cap >= max { Errno::E2big } else { Errno::Erange }));
    }
    Ok(())
}

/// `simple_xattr_list` — `trusted.*` names are invisible without CAP_SYS_ADMIN.
/// # C: O(1)
pub fn list_visible(name: &str, sys_admin: bool) -> bool {
    !(name.starts_with(TRUSTED_PREFIX) && !sys_admin)
}

/// `xattr_list_one` framing: each name is copied WITH its terminating NUL, so
/// the payload is a NUL-separated, NUL-terminated sequence. # C: O(total)
pub fn list_payload(names: &[String], sys_admin: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for n in names {
        if !list_visible(n, sys_admin) { continue; }
        out.extend_from_slice(&vfs::path_into_bytes(n));
        out.push(0);
    }
    out
}

/// `is_v2header`/`is_v3header` — the exact size+revision pairs
/// `cap_convert_nscap` accepts for a `security.capability` value. # C: O(1)
fn valid_cap_header(value: &[u8]) -> bool {
    if value.len() < 4 { return false; }
    let magic = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
    match magic & VFS_CAP_REVISION_MASK {
        VFS_CAP_REVISION_2 => value.len() == XATTR_CAPS_SZ_2,
        VFS_CAP_REVISION_3 => value.len() == XATTR_CAPS_SZ_3,
        _ => false,
    }
}

/// `cap_convert_nscap` + `cap_inode_setxattr`: a `security.capability` write
/// must carry a well-formed v2/v3 blob (`EINVAL`) and CAP_SETFCAP (`EPERM`);
/// any other `security.*` write needs CAP_SYS_ADMIN. Runs BEFORE
/// [`xattr_permission`], matching `vfs_setxattr`'s ordering. # C: O(1)
pub fn cap_set_gate(name: &str, value: &[u8], c: &XattrCred) -> Result<(), i64> {
    if !name.starts_with(SECURITY_PREFIX) { return Ok(()); }
    if name == NAME_CAPS {
        if value.is_empty() { return Ok(()); }
        if !valid_cap_header(value) { return Err(err(Errno::Einval)); }
        return if c.setfcap { Ok(()) } else { Err(err(Errno::Eperm)) };
    }
    if c.sys_admin { Ok(()) } else { Err(err(Errno::Eperm)) }
}

/// `cap_inode_removexattr`: dropping `security.capability` needs CAP_SETFCAP,
/// any other `security.*` needs CAP_SYS_ADMIN. # C: O(1)
pub fn cap_remove_gate(name: &str, c: &XattrCred) -> Result<(), i64> {
    if !name.starts_with(SECURITY_PREFIX) { return Ok(()); }
    if name == NAME_CAPS {
        return if c.setfcap { Ok(()) } else { Err(err(Errno::Eperm)) };
    }
    if c.sys_admin { Ok(()) } else { Err(err(Errno::Eperm)) }
}
