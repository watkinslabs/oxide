// The per-inode label: where an existing object's label comes from, and what
// a newly created one gets.

use alloc::string::{String, ToString};

use selinux::context::ValidContext;
use selinux::policydb::{FsUse, Genfs, Policydb};
use selinux::services::render::valid_context_to_string;
use selinux::sidtab::Sid;
use selinux::SecurityServer;

use crate::label::unlabeled_sid;

use super::sb::{context_sid, SuperblockSecurity};

/// Class value in a path-prefix entry that matches every class.
const GENFS_ANY_CLASS: u32 = 0;

/// Where one existing inode's label comes from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LabelPlan {
    /// This written context, or unlabeled if it does not resolve.
    Context(String),
    /// The mount's default label.
    Default,
    /// The creating task's label.
    TaskSid,
    /// A transition from the creating task over the mount's label.
    TransitionFromMount,
    /// No label at all.
    Unlabeled,
}

/// Where a newly created inode's label comes from.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NewInodePlan {
    /// The mount's single label, because the mount carries only one.
    MountSid,
    /// A label the creating task staged for its next object.
    Staged(Sid),
    /// A transition over the parent directory, keyed by the new name.
    Transition,
}

/// Source of one existing inode's label. # C: O(1)
///
/// A behaviour that reads the attribute falls back to the mount default when
/// the attribute is absent — an object written before the filesystem was
/// labelled is not thereby unreachable.
pub fn existing_inode_plan(behavior: FsUse, xattr: Option<&str>, genfs: Option<&str>)
    -> LabelPlan
{
    match behavior {
        FsUse::Xattr | FsUse::Native => match xattr {
            Some(w) => LabelPlan::Context(w.to_string()),
            None => LabelPlan::Default,
        },
        FsUse::Trans => LabelPlan::TransitionFromMount,
        FsUse::Task => LabelPlan::TaskSid,
        FsUse::Genfs => match genfs {
            Some(w) => LabelPlan::Context(w.to_string()),
            None => LabelPlan::Default,
        },
        FsUse::Mntpoint => LabelPlan::Default,
        FsUse::None => LabelPlan::Unlabeled,
    }
}

/// Context the policy's path prefixes give one path within a filesystem.
/// # C: O(paths)
///
/// The entries are ordered longest-prefix-first when the policy is read, so
/// the FIRST match is the most specific one. Re-ordering or scanning them any
/// other way returns a broader entry and mislabels every object beneath a
/// nested prefix.
pub fn genfs_context(db: &Policydb, fstype: &str, path: &str, kernel_class: u16)
    -> Option<String>
{
    let entry = db.genfs.iter().find(|g| g.fstype == fstype)?;
    let policy_class = policy_class_value(db, kernel_class).unwrap_or(GENFS_ANY_CLASS);
    let found = genfs_match(entry, path, policy_class)?;
    valid_context_to_string(db, found).ok()
}

/// Most specific prefix entry covering a path. # C: O(paths)
///
/// The table is already ordered longest-first, so this takes the first match
/// and imposes no order of its own. It is a named step rather than an inline
/// call so the ordering it depends on has somewhere to be tested.
pub fn genfs_match<'a>(entry: &'a Genfs, path: &str, policy_class: u32)
    -> Option<&'a ValidContext>
{
    entry.lookup(path, policy_class)
}

/// Policy class value of a kernel class. # C: O(classes)
///
/// The two numberings are independent: a policy numbers the classes it
/// declares, and this kernel numbers the classes it knows. Matching by name is
/// what keeps a path-prefix entry naming `file` from being tested against
/// whatever class happens to hold that number here.
fn policy_class_value(db: &Policydb, kernel_class: u16) -> Option<u32> {
    let name = selinux::uapi::classmap::class_def(kernel_class)?.name;
    db.symbols.classes.iter().find(|c| c.name == name).map(|c| c.value)
}

/// SID of an existing inode. # C: O(paths + categories)
///
/// `path` is the object's path within its own mount, which is what the
/// path-prefix table is written against; a path including the mount point
/// matches nothing.
pub fn existing_inode_sid(srv: &mut SecurityServer, sb: &SuperblockSecurity, task_sid: Sid,
                          class: u16, xattr: Option<&str>, path: Option<&str>) -> Sid
{
    let genfs = match sb.behavior {
        FsUse::Genfs => path.and_then(|p| {
            srv.policy().and_then(|db| genfs_context(db, &sb.fstype, p, class))
        }),
        _ => None,
    };
    match existing_inode_plan(sb.behavior, xattr, genfs.as_deref()) {
        LabelPlan::Context(w) => context_sid(srv, Some(&w)),
        LabelPlan::Default => sb.default_sid,
        LabelPlan::TaskSid => task_sid,
        LabelPlan::TransitionFromMount =>
            srv.transition_sid(task_sid, sb.sb_sid, class, None).unwrap_or_else(|_| unlabeled_sid()),
        LabelPlan::Unlabeled => unlabeled_sid(),
    }
}

/// Source of a newly created inode's label. # C: O(1)
///
/// A staged label beats the transition the policy would compute, which is what
/// makes an installer able to write a file with the label it intends rather
/// than the one its own domain implies.
pub fn new_inode_plan(behavior: FsUse, staged: Option<Sid>) -> NewInodePlan {
    if behavior == FsUse::Mntpoint { return NewInodePlan::MountSid; }
    match staged {
        Some(sid) => NewInodePlan::Staged(sid),
        None => NewInodePlan::Transition,
    }
}

/// SID of an inode being created in `dir_sid` under `name`. # C: O(rules)
///
/// The NAME is part of the question. A policy states filename transitions —
/// "a file called `shadow` created here is `shadow_t`" — and dropping the name
/// silently answers with the directory's ordinary transition instead, which
/// looks right and labels every such file wrong.
pub fn new_inode_sid(srv: &mut SecurityServer, sb: &SuperblockSecurity, staged: Option<Sid>,
                     task_sid: Sid, dir_sid: Sid, class: u16, name: Option<&str>) -> Sid
{
    match new_inode_plan(sb.behavior, staged) {
        NewInodePlan::MountSid => sb.sb_sid,
        NewInodePlan::Staged(sid) => sid,
        NewInodePlan::Transition => srv.transition_sid(task_sid, dir_sid, class, name)
            .unwrap_or_else(|_| unlabeled_sid()),
    }
}
