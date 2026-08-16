//! The two accounting arrangements, checked against what the mount already
//! has.
//!
//! Parsing settles the arrangements WITHIN one line. That is enough at a fresh
//! mount and wrong at a remount, where the line is read on top of a mount that
//! may already name files, already carry a format, and already have accounting
//! running. Three states only exist there:
//!
//! - **A name appearing or disappearing while accounting runs.** The open
//!   records are attached to the file that was named; swapping the name under
//!   them leaves them written to nothing.
//! - **A different name for a kind that already has one.** There is no answer:
//!   the two files hold different numbers for the same identity.
//! - **A name on a volume whose superblock names its own quota inodes.** The
//!   modern arrangement is already in force, so the name is dropped rather
//!   than refused — refusing would break a line that has carried it for years.

use syscall::errno::Errno;

use crate::opts::{Options, QKind, Spec};
use crate::opts::jquota::QKINDS;

use super::Sbi;

/// Settle the mount line's quota request against the running mount's.
/// # C: O(QKINDS)
pub fn check_quota_consistency(sbi: &Sbi, o: &mut Options, spec: &mut Spec)
    -> Result<(), Errno> {
    // Project accounting is stored IN the inode, so a volume without the field
    // has nowhere to put the id the enforcement would read.
    if o.prjquota && !crate::features::has_project_quota(sbi.facts.feature) {
        return Err(Errno::Einval);
    }
    let quota_feature = crate::features::has_quota_ino(sbi.facts.feature);
    for i in 0..QKINDS {
        if !spec.qname[i] { continue; }
        let old = sbi.cur.jquota.names[i];
        let new = o.jquota.names[i];
        if sbi.quota_on && old.is_some() != new.is_some() { return Err(Errno::Einval); }
        if let Some(had) = old {
            match new {
                // A bare spelling takes the file back out of the arrangement.
                None => continue,
                Some(now) if now == had => { spec.qname[i] = false; continue; }
                Some(_) => return Err(Errno::Einval),
            }
        }
        if quota_feature {
            spec.qname[i] = false;
            o.jquota.names[i] = None;
        }
    }
    // The mixture is judged over BOTH sides. A remount that names a file for a
    // kind the mount is already enforcing the modern way is the same conflict
    // as naming both on one line, and only the pair shows it.
    let named = |i: usize| sbi.cur.jquota.names[i].is_some() || o.jquota.names[i].is_some();
    let (usr_qf, grp_qf, prj_qf) =
        (named(QKind::User as usize), named(QKind::Group as usize),
         named(QKind::Project as usize));
    let mut usrquota = sbi.cur.usrquota || o.usrquota;
    let mut grpquota = sbi.cur.grpquota || o.grpquota;
    let mut prjquota = sbi.cur.prjquota || o.prjquota;
    // For a kind with a file, the file and the flag are the same request and
    // the file wins; a flag left standing belongs to a kind with no file.
    if usr_qf { o.usrquota = false; usrquota = false; }
    if grp_qf { o.grpquota = false; grpquota = false; }
    if prj_qf { o.prjquota = false; prjquota = false; }
    if usr_qf || grp_qf || prj_qf {
        if usrquota || grpquota || prjquota { return Err(Errno::Einval); }
        // Nothing in a quota file says which parser it wants, so a name with no
        // format on either side describes records nothing can read.
        if !spec.jqfmt && sbi.cur.jquota.fmt.is_none() && o.jquota.fmt.is_none() {
            return Err(Errno::Einval);
        }
    }
    Ok(())
}
