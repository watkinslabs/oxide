// The per-mount labelling decision.
//
// A mount decides ONCE how its inodes get labels, and every inode on it then
// follows that decision. Deciding per inode instead would let two objects on
// one filesystem be labelled by different rules, which is how a filesystem
// that cannot carry labels ends up with some that look authoritative.

use alloc::string::{String, ToString};

use selinux::policydb::{FsUse, Policydb};
use selinux::services::render::valid_context_to_string;
use selinux::sidtab::Sid;
use selinux::SecurityServer;

use crate::label::unlabeled_sid;

/// Class a filesystem's own root is looked up as when the policy states no
/// `fs_use` rule for it: the mount root is a directory.
const ROOT_CLASS: &str = "dir";
/// Path the mount root presents to a path-prefix lookup.
const ROOT_PATH: &str = "/";

/// Label-bearing mount options a caller may have parsed from the mount data.
///
/// Each one overrides a different part of the decision, so they are separate
/// fields rather than one context: `context=` replaces the whole scheme with a
/// single label, `fscontext=` renames only the filesystem object itself, and
/// `defcontext=` changes only what an unlabelled inode falls back to.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct MountOptions<'a> {
    /// `context=` — one label for every inode on the mount.
    pub context: Option<&'a str>,
    /// `fscontext=` — label of the filesystem object, not of its inodes.
    pub fscontext: Option<&'a str>,
    /// `defcontext=` — label an inode with no written one falls back to.
    pub defcontext: Option<&'a str>,
}

/// The mount decision, before any context has been resolved to a SID.
///
/// Kept separate from [`SuperblockSecurity`] so the decision itself is a pure
/// function of the policy and the options, testable without a SID table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SbPlan {
    /// How inodes on this mount get their labels.
    pub behavior: FsUse,
    /// Filesystem type name, which the path-prefix table is keyed by.
    pub fstype: String,
    /// Written context of the filesystem object itself.
    pub sb_context: Option<String>,
    /// Written context an inode falls back to when it carries none.
    pub default_context: Option<String>,
}

/// The mount decision with its contexts resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuperblockSecurity {
    /// How inodes on this mount get their labels.
    pub behavior: FsUse,
    /// Filesystem type name.
    pub fstype: String,
    /// SID of the filesystem object; the target of the `associate` check.
    pub sb_sid: Sid,
    /// SID an inode falls back to when it carries no label of its own.
    pub default_sid: Sid,
}

/// Decide how one mount labels its inodes. # C: O(fs_use entries + genfs paths)
///
/// `context=` wins outright: it states that this mount carries one label, so
/// nothing on it is consulted for another. Otherwise the policy's `fs_use`
/// statement decides; a filesystem the policy never names but does give path
/// prefixes for is labelled from those prefixes, and one it says nothing about
/// at all carries no labels rather than inheriting someone else's.
pub fn sb_plan(db: &Policydb, fstype: &str, opts: &MountOptions) -> SbPlan {
    if let Some(ctx) = opts.context {
        return SbPlan {
            behavior: FsUse::Mntpoint,
            fstype: fstype.to_string(),
            sb_context: Some(ctx.to_string()),
            default_context: Some(ctx.to_string()),
        };
    }
    let (behavior, stated) = match db.ocontexts.fs_use_of(fstype) {
        Some(f) => (f.behavior, valid_context_to_string(db, &f.context).ok()),
        None => genfs_root(db, fstype),
    };
    SbPlan {
        behavior,
        fstype: fstype.to_string(),
        sb_context: opts.fscontext.map(ToString::to_string).or_else(|| stated.clone()),
        default_context: opts.defcontext.map(ToString::to_string).or(stated),
    }
}

/// Behaviour and root context of a filesystem the policy states no `fs_use`
/// rule for. # C: O(genfs paths)
///
/// The path-prefix table standing in for the missing statement is what labels
/// the pseudo-filesystems; a filesystem absent from both tables carries no
/// labels, which is the honest answer rather than a borrowed one.
fn genfs_root(db: &Policydb, fstype: &str) -> (FsUse, Option<String>) {
    let class = selinux::uapi::classmap::class_by_name(ROOT_CLASS);
    let root = class.and_then(|c| super::resolve::genfs_context(db, fstype, ROOT_PATH, c));
    let names_fstype = db.genfs.iter().any(|g| g.fstype == fstype);
    if names_fstype { (FsUse::Genfs, root) } else { (FsUse::None, None) }
}

/// Resolve a mount decision's contexts against the loaded policy.
/// # C: O(fs_use entries + categories)
///
/// A context the policy cannot interpret leaves the mount unlabeled rather
/// than unmountable: refusing here would make one dropped type unmount the
/// system.
pub fn superblock_security(srv: &mut SecurityServer, fstype: &str, opts: &MountOptions)
    -> SuperblockSecurity
{
    let Some(db) = srv.policy() else {
        return SuperblockSecurity {
            behavior: FsUse::None,
            fstype: fstype.to_string(),
            sb_sid: unlabeled_sid(),
            default_sid: unlabeled_sid(),
        };
    };
    let plan = sb_plan(db, fstype, opts);
    SuperblockSecurity {
        behavior: plan.behavior,
        sb_sid: context_sid(srv, plan.sb_context.as_deref()),
        default_sid: context_sid(srv, plan.default_context.as_deref()),
        fstype: plan.fstype,
    }
}

/// SID of a written context, unlabeled when there is none or it does not
/// resolve. # C: O(categories)
pub fn context_sid(srv: &mut SecurityServer, written: Option<&str>) -> Sid {
    written.and_then(|w| srv.context_to_sid(w).ok()).unwrap_or_else(unlabeled_sid)
}
