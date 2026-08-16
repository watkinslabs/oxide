//! Which of the three kinds of accounting a volume actually offers.
//!
//! Two separate questions decide it, and conflating them is the bug this
//! module exists to prevent:
//!
//! - **Does the volume HAVE the file?** The superblock names an inode per
//!   kind. A zero there means the kind was never formatted in, and no mount
//!   option can conjure it.
//! - **Did the mount ask to ENFORCE it?** Usage is tracked for every kind the
//!   volume has, whether or not it was asked for — otherwise a mount that did
//!   not ask leaves the counts stale for the next mount that did. The option
//!   adds enforcement on top, and nothing else.
//!
//! One kind is different: project accounting also needs the volume's own
//! feature bit, because the identity it accounts against is stored in each
//! inode. Asking for it on a volume without that bit is refused at mount
//! rather than silently accounting everything to project zero.
//!
//! A volume with no quota inodes at all is not therefore unaccounted: the
//! mount may NAME an ordinary file in the volume's root per kind, in a format
//! it names too. Those files enforce from the moment they are opened — no
//! option asked for them separately, so there is no tracking-only half — and
//! the inode they live in is the caller's to resolve, because a name is
//! resolved by a lookup and nothing here reads a medium.

use crate::features;
use crate::flags::{CP_QUOTA_NEED_FSCK_FLAG, FEATURE_QUOTA_INO};
use crate::opts::Options;

use super::uapi::*;
use super::QuotaError;

/// The format a volume's own quota inodes are always in. The superblock names
/// the files, so nothing on the mount line has to.
pub const SYSFILE_FORMAT: u32 = vfs::QFMT_VFS_V1;

/// How far accounting goes for one kind.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Enforcement {
    /// Not accounted at all: the volume has no file for this kind.
    Off,
    /// Counts are maintained, but no allocation is ever refused.
    Usage,
    /// Counts are maintained and limits are enforced.
    UsageAndLimits,
}

/// What one kind resolves to on this mount.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Setup {
    /// The inode holding this kind's file, zero when there is none — and
    /// zero, with `named` set, when the mount gave a name the caller has yet
    /// to look up.
    pub ino: u32,
    pub enforcement: Enforcement,
    /// The format this kind's records are in. Zero when the kind is off.
    pub fmt: u32,
    /// Whether the file is the one the MOUNT named rather than the one the
    /// superblock names. The caller resolves the name to an inode; until it
    /// does, `ino` is zero and nothing can be read.
    pub named: bool,
}

impl Setup {
    /// A kind this volume does not account. # C: O(1)
    pub const OFF: Self =
        Self { ino: 0, enforcement: Enforcement::Off, fmt: 0, named: false };
}

/// Whether the volume stores its quota files as inodes named by the
/// superblock. Without this, the files are ordinary paths named at mount and
/// the superblock's inode numbers mean nothing. # C: O(1)
pub fn has_quota_ino(feature: u32) -> bool { feature & FEATURE_QUOTA_INO != 0 }

/// Whether `ino` is one of the volume's quota files.
///
/// Those files are not themselves accounted — charging a quota file's own
/// growth to the identity whose usage it records is unbounded recursion.
/// # C: O(1)
pub fn is_quota_inode(qf_ino: &[u32; MAX_QUOTAS], feature: u32, ino: u32) -> bool {
    has_quota_ino(feature) && ino != 0 && qf_ino.contains(&ino)
}

/// What each kind resolves to, given the volume and what the mount asked for.
///
/// A checkpoint that marked the quota files as needing repair suppresses all
/// three: continuing to account against a file known to be inconsistent
/// writes the inconsistency deeper, and the reference stops rather than
/// compounding it.
/// # C: O(1)
pub fn resolve(
    qf_ino: &[u32; MAX_QUOTAS],
    feature: u32,
    ckpt_flags: u32,
    opts: &Options,
) -> Result<[Setup; MAX_QUOTAS], QuotaError> {
    let asked = [opts.usrquota, opts.grpquota, opts.prjquota];
    if asked[PRJQUOTA] && !features::has_project_quota(feature) {
        return Err(QuotaError::NoProjectQuota);
    }
    let sysfiles = has_quota_ino(feature);
    let off = [Setup::OFF; MAX_QUOTAS];
    if ckpt_flags & CP_QUOTA_NEED_FSCK_FLAG != 0 { return Ok(off); }

    let mut out = off;
    if !sysfiles {
        // A named file is opened by name and enforces from the moment it is
        // opened: nothing else asked for it, so there is no tracking-only
        // half to fall back to.
        let Some(fmt) = opts.jquota.fmt else { return Ok(out) };
        for t in 0..MAX_QUOTAS {
            if opts.jquota.names[t].is_none() { continue; }
            out[t] = Setup {
                ino: 0,
                enforcement: Enforcement::UsageAndLimits,
                fmt: fmt as u32,
                named: true,
            };
        }
        return Ok(out);
    }
    for t in 0..MAX_QUOTAS {
        let ino = qf_ino[t];
        if ino == 0 { continue; }
        out[t] = Setup {
            ino,
            enforcement: if asked[t] { Enforcement::UsageAndLimits } else { Enforcement::Usage },
            fmt: SYSFILE_FORMAT,
            named: false,
        };
    }
    Ok(out)
}

/// Whether an allocation by this kind is measured against its limits.
/// # C: O(1)
pub fn enforced(s: &Setup) -> bool { s.enforcement == Enforcement::UsageAndLimits }

/// Whether this kind's counts are maintained at all. # C: O(1)
pub fn accounted(s: &Setup) -> bool { s.enforcement != Enforcement::Off }
