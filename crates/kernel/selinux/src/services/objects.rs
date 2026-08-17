// Contexts a policy states directly rather than deriving: per-filesystem path
// prefixes and the initial SIDs the kernel needs before any policy-labelled
// object exists.

use crate::context::{Context, ValidContext};
use crate::error::{Error, Result};
use crate::mapping::Mapping;
use crate::policydb::Policydb;
use crate::sidtab::{Sid, Sidtab};

/// Class value matching every class in a path-prefix entry.
const GENFS_ANY_CLASS: u32 = 0;

/// Context a filesystem's path-prefix entries give one path. # C: O(paths)
///
/// An unknown class still consults the table: entries that name no class match
/// every class, and refusing the lookup outright would leave objects of a
/// class this kernel does not know unlabelled inside a labelled filesystem.
pub fn genfs_sid<'a>(db: &'a Policydb, fstype: &str, path: &str, kernel_class: u16,
                     map: &Mapping) -> Option<&'a ValidContext> {
    let policy_class = map.policy_class(kernel_class).unwrap_or(GENFS_ANY_CLASS);
    db.genfs.iter().find(|g| g.fstype == fstype)?.lookup(path, policy_class)
}

/// Context the policy assigns one initial SID. # C: O(initial SIDs)
pub fn initial_sid_context(db: &Policydb, sid: Sid) -> Option<&ValidContext> {
    db.ocontexts.isid(sid)
}

/// Install every initial-SID context the policy declares. # C: O(initial SIDs)
///
/// An initial SID this kernel does not use is SKIPPED, not refused. Policies are
/// written against newer kernels than the one loading them, and refusing the
/// whole image over a SID nothing here will ever ask about would leave the
/// system with no policy at all. Only SID 0 is an error: it is the "no SID"
/// value, so a context assigned to it means the image is malformed.
///
/// The first user process's label is the exception that matters most. A policy
/// declares a context for it only when it advertises `userspace_initial_context`;
/// without that capability its declared context is a placeholder, and the SID
/// must instead resolve to the KERNEL's context — which is what every task
/// started before the policy load is expected to read back. Taking the declared
/// placeholder gives those tasks `unlabeled_t`, and userspace that reads its own
/// label to decide what to do then acts on a label the policy never meant it to
/// have.
pub fn load_initial_sids(db: &Policydb, sidtab: &mut Sidtab) -> Result<()> {
    use crate::uapi::initsid::{initsid_name, InitSid};
    use crate::uapi::policycap::POLICYDB_CAP_USERSPACE_INITIAL_CONTEXT;
    use crate::uapi::version::SECSID_NULL;
    let userspace_initial = db.policycap(POLICYDB_CAP_USERSPACE_INITIAL_CONTEXT);
    for isid in &db.ocontexts.isids {
        if isid.sid == SECSID_NULL { return Err(Error::Malformed); }
        // A SID this kernel has no name for is one it never asks about.
        if initsid_name(isid.sid).is_none() { continue; }
        if isid.sid == InitSid::Init.sid() && !userspace_initial { continue; }
        sidtab.set_initial(isid.sid, Context::Valid(isid.context.clone()))?;
        if isid.sid == InitSid::Kernel.sid() && !userspace_initial {
            sidtab.set_initial(InitSid::Init.sid(), Context::Valid(isid.context.clone()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/objects.rs"]
mod tests;
