//! Quota files named on the mount line, and the format they are in.
//!
//! Two accounting arrangements exist and a mount may use exactly one. The
//! modern one keeps the records in hidden inodes the superblock names, and
//! `usrquota`/`grpquota`/`prjquota` only say whether the limits are enforced.
//! The legacy one keeps them in ORDINARY FILES in the volume's root, named
//! here, and the format those files are in is not discoverable from their
//! contents — `jqfmt=` is the only thing that says which parser to use.
//!
//! Three rules, each of which is a silent wrong answer if skipped:
//!
//! - **The name is a root-directory entry, never a path.** A name containing a
//!   separator is refused rather than resolved, because resolving it would let
//!   a mount point its accounting at a file on another filesystem.
//! - **Naming a file and asking for the modern enforcement is a conflict**,
//!   not a merge: the two would keep separate records for the same identity
//!   and each would be wrong.
//! - **A named file with no format is refused.** Guessing the format reads the
//!   wrong structure out of a real file and reports limits nobody set.

use syscall::errno::Errno;

use crate::uapi::NAME_LEN;

/// Which on-disk record layout the named files are in.
///
/// The numbers are the ones the quota interface carries, so a mount and a
/// later `quotactl` agree about what a format id means.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum JqFmt {
    /// The original layout, one fixed-size record per identity.
    VfsOld = 1,
    /// The tree layout.
    VfsV0 = 2,
    /// The tree layout with wider counters.
    VfsV1 = 4,
}

impl JqFmt {
    /// # C: O(1)
    pub fn parse(v: &str) -> Option<JqFmt> {
        match v {
            "vfsold" => Some(JqFmt::VfsOld),
            "vfsv0" => Some(JqFmt::VfsV0),
            "vfsv1" => Some(JqFmt::VfsV1),
            _ => None,
        }
    }

    /// # C: O(1)
    pub fn name(self) -> &'static str {
        match self {
            JqFmt::VfsOld => "vfsold",
            JqFmt::VfsV0 => "vfsv0",
            JqFmt::VfsV1 => "vfsv1",
        }
    }
}

/// The three kinds of identity a quota file can account for, in the order the
/// quota interface numbers them.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum QKind {
    User = 0,
    Group = 1,
    Project = 2,
}

/// How many kinds there are.
pub const QKINDS: usize = 3;

/// A quota file's name.
///
/// Stored inline rather than on the heap so the option set stays a plain value
/// that can be copied into a mount without an allocation on a path that must
/// not fail. The bound is the longest name this filesystem's directories can
/// hold, so nothing a volume could actually contain is refused for length.
#[derive(Copy, Clone)]
pub struct QfName {
    bytes: [u8; NAME_LEN],
    len: u8,
}

impl QfName {
    /// The name, or `Enametoolong`/`Einval` for one this filesystem could
    /// never resolve. # C: O(len)
    pub fn new(s: &str) -> Result<QfName, Errno> {
        let b = s.as_bytes();
        if b.is_empty() { return Err(Errno::Einval); }
        if b.len() > NAME_LEN { return Err(Errno::Enametoolong); }
        // A quota file is an entry in the volume's own root. A name carrying a
        // separator is asking for a path, and a path could leave the volume.
        if b.contains(&b'/') { return Err(Errno::Einval); }
        let mut bytes = [0u8; NAME_LEN];
        bytes[..b.len()].copy_from_slice(b);
        Ok(QfName { bytes, len: b.len() as u8 })
    }

    /// # C: O(1)
    pub fn as_bytes(&self) -> &[u8] { &self.bytes[..self.len as usize] }

    /// # C: O(len)
    pub fn as_str(&self) -> &str {
        // A name only ever enters through `new`, which took a `&str`.
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }
}

impl PartialEq for QfName {
    fn eq(&self, other: &Self) -> bool { self.as_bytes() == other.as_bytes() }
}
impl Eq for QfName {}

impl core::fmt::Debug for QfName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the mount line said about legacy quota files.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Jquota {
    /// One name per kind, in `QKind` order.
    pub names: [Option<QfName>; QKINDS],
    pub fmt: Option<JqFmt>,
}

impl Jquota {
    /// Name the file for `kind`, or clear it when the option carried no value.
    ///
    /// Naming the same file twice is accepted and naming a different one is
    /// refused: an option string assembled from two places that agree is not a
    /// conflict, and one that disagrees has no answer.
    /// # C: O(len)
    pub fn note(&mut self, kind: QKind, value: Option<&str>) -> Result<(), Errno> {
        let slot = kind as usize;
        let Some(v) = value.filter(|v| !v.is_empty()) else {
            self.names[slot] = None;
            return Ok(());
        };
        let name = QfName::new(v)?;
        match self.names[slot] {
            Some(had) if had != name => Err(Errno::Einval),
            _ => { self.names[slot] = Some(name); Ok(()) }
        }
    }

    /// Whether any kind names a file. # C: O(1)
    pub fn any_named(&self) -> bool { self.names.iter().any(Option::is_some) }
}

/// Settle the two arrangements against each other, or refuse the pair.
///
/// One pass, because the settling and the refusal are the same decision seen
/// twice: for a kind that names a file, the file and the flag mean the same
/// request and the file wins, so the flag is cleared. A flag left standing
/// afterwards belongs to a kind with NO file, which is a genuine mixture — one
/// kind accounted in a hidden inode and another in a root file — and there is
/// no arrangement that serves both. A named file with no format is refused for
/// the same reason: nothing in the file says which parser it wants.
/// # C: O(1)
pub fn settle(j: &Jquota, usrquota: &mut bool, grpquota: &mut bool, prjquota: &mut bool)
    -> Result<(), Errno>
{
    if !j.any_named() { return Ok(()); }
    if j.names[QKind::User as usize].is_some() { *usrquota = false; }
    if j.names[QKind::Group as usize].is_some() { *grpquota = false; }
    if j.names[QKind::Project as usize].is_some() { *prjquota = false; }
    if *usrquota || *grpquota || *prjquota { return Err(Errno::Einval); }
    if j.fmt.is_none() { return Err(Errno::Einval); }
    Ok(())
}
