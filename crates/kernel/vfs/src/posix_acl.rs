// POSIX ACL entry model and the two format-independent decisions every
// filesystem that stores ACLs has to make: fold an access ACL into `i_mode`
// (`posix_acl_equiv_mode`), and derive a new object's mode plus inherited ACLs
// from its parent directory's DEFAULT ACL (`posix_acl_create`).
//
// The codec here is the INTERCHANGE form — `struct posix_acl_xattr_header` +
// `struct posix_acl_xattr_entry`, version 2, a fixed 8 bytes per entry — which
// is what `set/getxattr` carries and what a filesystem with no on-disk ACL
// format of its own stores verbatim. A filesystem that has its own on-disk
// record converts at its own `i_op` xattr boundary and uses these entries in
// between.
//
// Umask note: for a POSIX-ACL-capable filesystem the VFS does NOT strip the
// umask before `->create` (`mode_strip_umask` is a no-op once the superblock
// says so); the strip happens HERE, and only when the parent carries no default
// ACL. A parent with a default ACL overrides the umask entirely.

extern crate alloc;
use alloc::vec::Vec;

/// The ON-DISK record every filesystem in the ext2/3/4 + f2fs family stores,
/// which is not the interchange form this module's own codec carries.
pub mod disk;

use syscall::errno::Errno;

use crate::types::{S_IRWXG, S_IRWXO, S_IRWXU, S_IRWXUGO};

/// The attribute name each ACL is carried under. `getfacl`/`setfacl` name these
/// directly, and a filesystem with its own on-disk record converts at the
/// boundary they cross.
pub const XATTR_NAME_ACL_ACCESS:  &str = "system.posix_acl_access";
pub const XATTR_NAME_ACL_DEFAULT: &str = "system.posix_acl_default";

/// Which of the two ACLs an object carries (`ACL_TYPE_ACCESS`/`ACL_TYPE_DEFAULT`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AclType {
    /// The one that DECIDES access to this object.
    Access,
    /// The template a directory hands to what is created inside it.
    Default,
}

impl AclType {
    /// The attribute name this type is stored under. # C: O(1)
    pub fn xattr_name(self) -> &'static str {
        match self { AclType::Access => XATTR_NAME_ACL_ACCESS, AclType::Default => XATTR_NAME_ACL_DEFAULT }
    }
    /// The type an attribute name selects, if it names an ACL at all. # C: O(1)
    pub fn from_xattr_name(name: &str) -> Option<Self> {
        match name {
            XATTR_NAME_ACL_ACCESS  => Some(AclType::Access),
            XATTR_NAME_ACL_DEFAULT => Some(AclType::Default),
            _ => None,
        }
    }
}

/// `ACL_*` entry tags.
pub const ACL_USER_OBJ:  u16 = 0x01;
pub const ACL_USER:      u16 = 0x02;
pub const ACL_GROUP_OBJ: u16 = 0x04;
pub const ACL_GROUP:     u16 = 0x08;
pub const ACL_MASK:      u16 = 0x10;
pub const ACL_OTHER:     u16 = 0x20;
/// `POSIX_ACL_XATTR_VERSION`.
pub const ACL_XATTR_VERSION: u32 = 2;
/// `ACL_UNDEFINED_ID` — the `e_id` of an entry that names no id.
pub const ACL_UNDEFINED_ID: u32 = u32::MAX;
/// `sizeof(struct posix_acl_xattr_header)` / `..._entry`.
pub const ACL_HDR_LEN:   usize = 4;
pub const ACL_ENTRY_LEN: usize = 8;
/// `ACL_READ|ACL_WRITE|ACL_EXECUTE` — every legal `e_perm` bit.
pub const ACL_PERM_MASK: u16 = 0o7;

/// One `struct posix_acl_entry`. `id` is `ACL_UNDEFINED_ID` for the four
/// entries that name no id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AclEntry { pub tag: u16, pub perm: u16, pub id: u32 }

/// `posix_acl_from_xattr` — decode the interchange blob. An empty entry list
/// decodes to an empty vector, which every caller reads as Linux's `NULL` ACL.
/// # C: O(N_entries)
pub fn from_xattr(value: &[u8]) -> Result<Vec<AclEntry>, Errno> {
    if value.len() < ACL_HDR_LEN { return Err(Errno::Einval); }
    let ver = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
    if ver != ACL_XATTR_VERSION { return Err(Errno::Eopnotsupp); }
    let body = &value[ACL_HDR_LEN..];
    if body.len() % ACL_ENTRY_LEN != 0 { return Err(Errno::Einval); }
    let mut out = Vec::with_capacity(body.len() / ACL_ENTRY_LEN);
    for e in body.chunks_exact(ACL_ENTRY_LEN) {
        out.push(AclEntry {
            tag:  u16::from_le_bytes([e[0], e[1]]),
            perm: u16::from_le_bytes([e[2], e[3]]),
            id:   u32::from_le_bytes([e[4], e[5], e[6], e[7]]),
        });
    }
    Ok(out)
}

/// `posix_acl_to_xattr` — encode entries back into the interchange blob.
/// # C: O(N_entries)
pub fn to_xattr(entries: &[AclEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ACL_HDR_LEN + entries.len() * ACL_ENTRY_LEN);
    out.extend_from_slice(&ACL_XATTR_VERSION.to_le_bytes());
    for e in entries {
        out.extend_from_slice(&e.tag.to_le_bytes());
        out.extend_from_slice(&e.perm.to_le_bytes());
        out.extend_from_slice(&e.id.to_le_bytes());
    }
    out
}

/// `posix_acl_valid` — the entry sequence must be USER_OBJ, USER*, GROUP_OBJ,
/// GROUP*, MASK?, OTHER, a MASK is mandatory once any USER/GROUP entry exists,
/// and no `e_perm` bit outside rwx may be set. # C: O(N_entries)
pub fn validate(entries: &[AclEntry]) -> Result<(), Errno> {
    let einval = Err(Errno::Einval);
    // `state` tracks which tag is legal next; 0 means "sequence complete".
    let mut state = ACL_USER_OBJ;
    let mut needs_mask = false;
    for e in entries {
        if e.perm & !ACL_PERM_MASK != 0 { return einval; }
        match e.tag {
            ACL_USER_OBJ  => { if state != ACL_USER_OBJ { return einval; } state = ACL_USER; }
            ACL_USER      => { if state != ACL_USER { return einval; } needs_mask = true; }
            ACL_GROUP_OBJ => { if state != ACL_USER { return einval; } state = ACL_GROUP; }
            ACL_GROUP     => { if state != ACL_GROUP { return einval; } needs_mask = true; }
            ACL_MASK      => { if state != ACL_GROUP { return einval; } state = ACL_OTHER; }
            ACL_OTHER     => {
                if state == ACL_OTHER || (state == ACL_GROUP && !needs_mask) { state = 0; }
                else { return einval; }
            }
            _ => return einval,
        }
    }
    if state == 0 { Ok(()) } else { einval }
}

/// `posix_acl_equiv_mode` — fold the three base entries into permission bits.
/// `Ok(true)` when the ACL carries information the mode bits CANNOT express (a
/// named user/group or a mask), i.e. Linux's `not_equiv`; an unknown tag is
/// `EINVAL`. # C: O(N_entries)
pub fn equiv_mode(entries: &[AclEntry], mode: &mut u16) -> Result<bool, Errno> {
    let mut perm: u16 = 0;
    let mut not_equiv = false;
    for e in entries {
        match e.tag {
            ACL_USER_OBJ  => perm |= (e.perm & S_IRWXO) << 6,
            ACL_GROUP_OBJ => perm |= (e.perm & S_IRWXO) << 3,
            ACL_OTHER     => perm |= e.perm & S_IRWXO,
            ACL_MASK      => { perm = (perm & !S_IRWXG) | ((e.perm & S_IRWXO) << 3); not_equiv = true; }
            ACL_USER | ACL_GROUP => not_equiv = true,
            _ => return Err(Errno::Einval),
        }
    }
    *mode = (*mode & !S_IRWXUGO) | perm;
    Ok(not_equiv)
}

/// `posix_acl_create_masq` — fold the requested mode INTO a clone of the
/// parent's default ACL and the clone's base entries back OUT into the mode, so
/// the created object's mode and its access ACL agree. `Ok(true)` when the
/// result still carries a named entry or a mask and must therefore be STORED as
/// an access ACL; `Ok(false)` when the mode bits say all of it.
///
/// An ACL with no MASK and no GROUP_OBJ cannot express the group permission bits
/// at all, so it is corruption rather than a bad argument: `EIO`, like an
/// unknown tag. # C: O(N_entries)
pub fn create_masq(entries: &mut [AclEntry], mode_p: &mut u16) -> Result<bool, Errno> {
    let mut mode = *mode_p;
    let mut not_equiv = false;
    // Indices, not references: the group/mask entry is revisited after the walk.
    let mut group_obj: Option<usize> = None;
    let mut mask_obj:  Option<usize> = None;
    for (i, e) in entries.iter_mut().enumerate() {
        match e.tag {
            ACL_USER_OBJ => {
                e.perm &= (mode >> 6) | !S_IRWXO;
                mode &= (e.perm << 6) | !S_IRWXU;
            }
            ACL_USER | ACL_GROUP => not_equiv = true,
            ACL_GROUP_OBJ => group_obj = Some(i),
            ACL_OTHER => {
                e.perm &= mode | !S_IRWXO;
                mode &= e.perm | !S_IRWXO;
            }
            ACL_MASK => { mask_obj = Some(i); not_equiv = true; }
            _ => return Err(Errno::Eio),
        }
    }
    let i = match mask_obj { Some(i) => i, None => match group_obj {
        Some(i) => i, None => return Err(Errno::Eio) } };
    entries[i].perm &= (mode >> 3) | !S_IRWXO;
    mode &= (entries[i].perm << 3) | !S_IRWXG;
    *mode_p = (*mode_p & !S_IRWXUGO) | (mode & S_IRWXUGO);
    Ok(not_equiv)
}

/// What a new object under a directory gets: its mode, and the two ACLs to
/// store on it. `None` means "store nothing", which is Linux's `NULL` ACL.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NewAcls {
    /// The mode to create the object with, permission bits already resolved.
    pub mode: u16,
    /// `system.posix_acl_access` for the new object.
    pub access: Option<Vec<AclEntry>>,
    /// `system.posix_acl_default` — a DIRECTORY inherits its parent's verbatim.
    pub default: Option<Vec<AclEntry>>,
}

/// What kind of object is being created; a symlink takes neither ACL nor umask.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NewKind { Dir, Symlink, Other }

/// `posix_acl_create` — decide a new object's mode and inherited ACLs from
/// `parent_default`, the parent directory's stored default ACL. A caller whose
/// superblock does not support POSIX ACLs (`IS_POSIXACL`, the `acl` mount
/// option) passes `None`, which is the same decision Linux reaches through
/// `mode_strip_umask`: the umask alone.
///
/// Order, which the mode depends on: a symlink is exempt outright; a parent
/// that carries no default ACL leaves the umask to decide the mode; with a
/// default ACL the umask is IGNORED and
/// `create_masq` decides both the mode and whether an access ACL is stored.
/// Only a directory inherits the default ACL itself. # C: O(N_entries)
pub fn acl_create(parent_default: Option<&[AclEntry]>, mode: u16, umask: u16, kind: NewKind)
    -> Result<NewAcls, Errno>
{
    let plain = |m: u16| NewAcls { mode: m, access: None, default: None };
    if kind == NewKind::Symlink { return Ok(plain(mode)); }
    let dflt = match parent_default {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(plain(mode & !umask)),
    };
    let mut clone: Vec<AclEntry> = dflt.to_vec();
    let mut mode = mode;
    let keep = create_masq(&mut clone, &mut mode)?;
    Ok(NewAcls {
        mode,
        access:  if keep { Some(clone) } else { None },
        default: if kind == NewKind::Dir { Some(dflt.to_vec()) } else { None },
    })
}

/// `posix_acl_permission` — decide `want` (r/w/x bits) against an access ACL.
/// `Ok(())` grants, `EACCES` denies, `EIO` is a malformed ACL — an unknown tag,
/// or a sequence that never reaches `ACL_OTHER`. A malformed ACL is never a
/// fall-through to the mode bits: the entries are the authority, and one that
/// cannot be read means the object's permissions are unknown.
///
/// The order is the one the format fixes and the class the caller lands in is
/// FINAL — a caller who matched a group entry that does not grant is refused
/// rather than falling to `other`, and the group/named grant is tested against
/// the entry's own bits BEFORE the mask narrows it, so the first entry whose
/// own bits cover the request decides the answer either way.
/// # C: O(N_entries)
pub fn permission<G>(entries: &[AclEntry], caller_uid: u32, i_uid: u32, i_gid: u32,
                     want: u16, in_group: G) -> Result<(), Errno>
    where G: Fn(u32) -> bool
{
    let want = want & ACL_PERM_MASK;
    let mut found = false;
    for (i, e) in entries.iter().enumerate() {
        match e.tag {
            // The owner is normally decided by the mode bits before the ACL is
            // consulted at all; this arm answers the callers that do not.
            ACL_USER_OBJ  => if caller_uid == i_uid { return granted(e.perm, want); },
            ACL_USER      => if caller_uid == e.id { return masked(entries, i, e.perm, want); },
            ACL_GROUP_OBJ => if in_group(i_gid) {
                found = true;
                if e.perm & want == want { return masked(entries, i, e.perm, want); }
            },
            ACL_GROUP     => if in_group(e.id) {
                found = true;
                if e.perm & want == want { return masked(entries, i, e.perm, want); }
            },
            ACL_MASK      => {}
            ACL_OTHER     => {
                if found { return Err(Errno::Eacces); }
                return granted(e.perm, want);
            }
            _ => return Err(Errno::Eio),
        }
    }
    Err(Errno::Eio)
}

fn granted(perm: u16, want: u16) -> Result<(), Errno> {
    if perm & want == want { Ok(()) } else { Err(Errno::Eacces) }
}

/// The verdict for an entry that the MASK limits: the mask entry follows the
/// entry that matched, so the search starts after it.
fn masked(entries: &[AclEntry], at: usize, perm: u16, want: u16) -> Result<(), Errno> {
    match entries[at + 1..].iter().find(|m| m.tag == ACL_MASK) {
        Some(m) => granted(perm & m.perm, want),
        None    => granted(perm, want),
    }
}

/// `__posix_acl_chmod_masq` — rewrite an access ACL so it says what the new mode
/// says. Without it a `chmod` on an object carrying an ACL would change the mode
/// bits and change nothing about the access the ACL grants, which is the one way
/// a permission check can disagree with what `ls -l` reports.
///
/// The group bits land on the MASK when the ACL has one and on `GROUP_OBJ` when
/// it does not — the same entry `equiv_mode` folds them out of. An ACL with
/// neither cannot express them: `EIO`. # C: O(N_entries)
pub fn chmod_masq(entries: &mut [AclEntry], mode: u16) -> Result<(), Errno> {
    let mut group_obj: Option<usize> = None;
    let mut mask_obj:  Option<usize> = None;
    for (i, e) in entries.iter_mut().enumerate() {
        match e.tag {
            ACL_USER_OBJ  => e.perm = (mode & S_IRWXU) >> 6,
            ACL_USER | ACL_GROUP => {}
            ACL_GROUP_OBJ => group_obj = Some(i),
            ACL_MASK      => mask_obj = Some(i),
            ACL_OTHER     => e.perm = mode & S_IRWXO,
            _ => return Err(Errno::Eio),
        }
    }
    let i = match mask_obj { Some(i) => i, None => match group_obj {
        Some(i) => i, None => return Err(Errno::Eio) } };
    entries[i].perm = (mode & S_IRWXG) >> 3;
    Ok(())
}

#[cfg(test)]
#[path = "tests/posix_acl.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/posix_acl_permission.rs"]
mod permission_tests;
