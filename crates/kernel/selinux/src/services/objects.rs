// Contexts a policy states directly rather than deriving: per-filesystem path
// prefixes and the initial SIDs the kernel needs before any policy-labelled
// object exists.

use crate::context::{Context, ValidContext};
use crate::error::Result;
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
pub fn load_initial_sids(db: &Policydb, sidtab: &mut Sidtab) -> Result<()> {
    for isid in &db.ocontexts.isids {
        sidtab.set_initial(isid.sid, Context::Valid(isid.context.clone()))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/objects.rs"]
mod tests;
