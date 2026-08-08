// Root-attribute mount options for the pseudo-filesystems whose whole option
// surface is "who owns the mount root, and how open is it".
//
// Several unrelated Linux pseudo-filesystems share one option shape — a
// `kuid`/`kgid`/`umode_t` triple plus a bitfield recording which of them the
// mount actually named — because the thing they configure is the same: the
// inode at the top of the tree. tracefs, debugfs and efivarfs are the three
// registered here; each publishes its OWN key list (efivarfs takes no `mode`,
// debugfs additionally takes `source`) and the list is what this module parses
// against, so a key can never be declared in one place and consumed in another.
//
// `Option` per field, not a value plus a "was it set" flag: the flag exists in
// the reference only because C has no option type, and it is read exactly as
// "did the mount name this" — at a reconfigure, where an unnamed field must
// keep the value the live instance already has rather than be reset to a
// default the caller never asked for.
//
// UNGATED: every value here decides an access-control answer on a mount root,
// so the whole decision surface must be reachable by `cargo test` on the host.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;

use vfs::fs::{FsParamSpec, FsParamType, FsParamVerdict, FsParameter, FsValue};
use vfs::VfsError;

use crate::tree::PseudoDir;

/// `S_IALLUGO` — the caller-settable half of a mode. `mode=` is masked with it
/// so a mount cannot smuggle a file-type bit into the root inode's mode.
pub const S_IALLUGO: u16 = 0o7777;

/// What a pseudo-filesystem root is born as when no mount ever names an owner:
/// root-owned and world-readable/searchable.
pub const DEFAULT_ROOT_PERM: u16 = 0o755;
/// The `uid`/`gid` a pseudo-filesystem tree node is born with.
pub const DEFAULT_ROOT_UID: u32 = 0;
/// See [`DEFAULT_ROOT_UID`].
pub const DEFAULT_ROOT_GID: u32 = 0;

/// Owner and permission bits a pseudo-directory's inode is created with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DirAttr {
    pub uid:  u32,
    pub gid:  u32,
    pub perm: u16,
}

impl Default for DirAttr {
    /// # C: O(1)
    fn default() -> Self {
        DirAttr { uid: DEFAULT_ROOT_UID, gid: DEFAULT_ROOT_GID, perm: DEFAULT_ROOT_PERM }
    }
}

/// One mount's answer to "who owns the root and how open is it". A field left
/// `None` was not named by the mount.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct RootAttrOpts {
    pub uid:  Option<u32>,
    pub gid:  Option<u32>,
    pub mode: Option<u16>,
}

impl RootAttrOpts {
    /// Fold this mount's answers onto `base`, leaving every field the mount did
    /// not name exactly as it was. A fresh mount folds onto
    /// [`DirAttr::default`]; a reconfigure folds onto what the live instance
    /// already carries, which is why an unnamed field must not be defaulted.
    /// # C: O(1)
    pub fn apply_to(&self, base: DirAttr) -> DirAttr {
        DirAttr {
            uid:  self.uid.unwrap_or(base.uid),
            gid:  self.gid.unwrap_or(base.gid),
            perm: self.mode.unwrap_or(base.perm),
        }
    }

    /// Did this mount name anything at all? # C: O(1)
    pub fn is_empty(&self) -> bool {
        self.uid.is_none() && self.gid.is_none() && self.mode.is_none()
    }
}

/// What a filesystem does with a key its table does not list.
///
/// Most refuse it — that refusal is what makes an option-support probe
/// truthful. debugfs does not: its parse swallows the "no such parameter"
/// answer and returns success, so `mount -t debugfs -o anything` succeeds. That
/// is a per-filesystem property of the reference, not a choice, and a
/// filesystem that refuses must not be made lenient to match one that does not.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnknownKey { Refuse, Ignore }

/// `{tracefs,debugfs}_fs_info` minus `source`: the three keys that name the
/// root inode's owner and mode.
pub static ROOT_ATTR_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::value("gid",  FsParamType::U32),
    FsParamSpec::value("mode", FsParamType::U32Oct),
    FsParamSpec::value("uid",  FsParamType::U32),
];

/// debugfs additionally carries `source`, which the VFS consumes before the
/// filesystem sees it; it is listed because the reference lists it, so a
/// support probe reads the same answer.
pub static ROOT_ATTR_SOURCE_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::value("gid",    FsParamType::U32),
    FsParamSpec::value("mode",   FsParamType::U32Oct),
    FsParamSpec::value("source", FsParamType::String),
    FsParamSpec::value("uid",    FsParamType::U32),
];

/// efivarfs: owner only. It has no `mode=`, so `mount -t efivarfs -o mode=700`
/// must FAIL, and it does only because this table is a different table.
pub static OWNER_ONLY_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::value("gid", FsParamType::U32),
    FsParamSpec::value("uid", FsParamType::U32),
];

/// The declaration a filesystem that accepts NO mount option publishes.
///
/// An empty table is a real statement, not the absence of one: the VFS admits
/// every key against it, finds none, and reports the parameter unknown — which
/// is exactly what the reference does for a type whose context operations
/// carry no `parse_param` at all. `None` would mean the opposite: swallow the
/// blob whole and refuse nothing.
///
/// Used by every registered type whose reference declares no parameters —
/// sysfs, configfs, securityfs, fusectl, mqueue and binfmt_misc.
pub static NO_PARAMETERS: &[FsParamSpec] = &[];

/// Consume one ALREADY-ADMITTED `key`/`value` into `opts`.
///
/// Returns whether the parameter named a root attribute. `false` is not
/// "unknown": admission has already established that the filesystem declares
/// this key, so `false` means the key is declared and answered somewhere other
/// than the root inode — `source`, which the VFS records before a filesystem is
/// consulted, and bpffs's `delegate_*`, which the token subsystem answers.
/// A caller that needs every declared name to land HERE checks the return.
/// # C: O(len value)
pub fn apply_param(opts: &mut RootAttrOpts, key: &str, value: Option<&str>) -> Result<bool, ()> {
    match (key, value) {
        ("uid", Some(v)) => opts.uid = Some(parse_dec(v)?),
        ("gid", Some(v)) => opts.gid = Some(parse_dec(v)?),
        // `fsparam_u32oct`: the value is OCTAL. Read as decimal, `mode=755`
        // would be 0o1363 — a setuid bit plus a mode nobody asked for.
        ("mode", Some(v)) => opts.mode = Some((parse_oct(v)? as u16) & S_IALLUGO),
        ("uid", None) | ("gid", None) | ("mode", None) => return Err(()),
        _ => return Ok(false),
    }
    Ok(true)
}

fn parse_dec(v: &str) -> Result<u32, ()> {
    if v.is_empty() { return Err(()); }
    v.parse::<u32>().map_err(|_| ())
}

fn parse_oct(v: &str) -> Result<u32, ()> {
    if v.is_empty() { return Err(()); }
    u32::from_str_radix(v, 8).map_err(|_| ())
}

/// Build one mount's root attributes from the `mount(2)` option BLOB, admitted
/// against `specs` — the same table the VFS publishes for the type, so a key
/// cannot be accepted here and refused there (or the reverse).
///
/// A pinned parameter is refused outright: none of these filesystems declares a
/// descriptor- or path-valued option, so a pinned value can only have arrived
/// by a caller naming a parameter this type does not take.
/// # C: O(len data * N_specs)
pub fn opts_for_mount(specs: &'static [FsParamSpec], data: &str, pinned: &[FsParameter],
    unknown: UnknownKey) -> Result<RootAttrOpts, VfsError>
{
    if !pinned.is_empty() { return Err(VfsError::Einval); }
    let mut opts = RootAttrOpts::default();
    for p in vfs::fs::split_monolithic(data) {
        match vfs::fs::admit_fs_param(specs, &p) {
            FsParamVerdict::Accept(_) => {}
            // A key inside the table given the wrong value shape is refused by
            // every one of these filesystems, lenient or not: the reference
            // swallows only the "no such parameter" answer, never a bad value.
            FsParamVerdict::WrongValueShape(_) => return Err(VfsError::Einval),
            FsParamVerdict::Unknown => match unknown {
                UnknownKey::Refuse => return Err(VfsError::Einval),
                UnknownKey::Ignore => continue,
            },
        }
        let value = match &p.value {
            FsValue::String(s) => Some(s.as_str()),
            FsValue::Flag => None,
            _ => return Err(VfsError::Einval),
        };
        // The return says whether the key named a root attribute; a declared
        // key answered elsewhere (`source`, bpffs's `delegate_*`) legitimately
        // says no. Which tables may contain such a key is the caller's
        // contract, pinned by its own test, not something to decide per blob.
        let _ = apply_param(&mut opts, p.key.as_str(), value).map_err(|_| VfsError::Einval)?;
    }
    Ok(opts)
}

/// Stamp a mount's root attributes onto the tree root it mounted.
///
/// This is the whole enforcement: the root inode a `stat` sees, and the owner
/// and mode every permission check on the mount point consults, come from the
/// node this writes. A mount that names nothing writes nothing, so it cannot
/// reset a value an earlier mount of the same shared tree established.
/// # C: O(1)
pub fn apply_root_attr(root: &Arc<PseudoDir>, opts: &RootAttrOpts) {
    if opts.is_empty() { return; }
    let next = opts.apply_to(root.attr());
    root.set_attr(next);
}

/// Render for `/proc/mounts`: only what the mount named, in the spelling it is
/// read back in. # C: O(1)
pub fn show_options(opts: &RootAttrOpts) -> String {
    let mut s = String::new();
    if let Some(u) = opts.uid { s.push_str(",uid="); push_dec(&mut s, u); }
    if let Some(g) = opts.gid { s.push_str(",gid="); push_dec(&mut s, g); }
    if let Some(m) = opts.mode { s.push_str(",mode="); push_oct3(&mut s, m); }
    s
}

fn push_dec(s: &mut String, mut v: u32) {
    if v == 0 { s.push('0'); return; }
    let mut buf = [0u8; 10];
    let mut n = 0;
    while v > 0 { buf[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
    while n > 0 { n -= 1; s.push(buf[n] as char); }
}

/// `%03o` — three octal digits minimum, so `mode=020` does not render as
/// `mode=20` and read back as a different value.
fn push_oct3(s: &mut String, v: u16) {
    let mut buf = [0u8; 6];
    let mut n = 0;
    let mut x = v;
    while x > 0 { buf[n] = b'0' + (x % 8) as u8; x /= 8; n += 1; }
    while n < 3 { buf[n] = b'0'; n += 1; }
    while n > 0 { n -= 1; s.push(buf[n] as char); }
}

#[cfg(test)]
mod tests;
