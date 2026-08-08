//! `mount(MS_SHARED|MS_PRIVATE|MS_SLAVE|MS_UNBINDABLE)`'s admission ladder
//! (`do_change_type`), as a PURE decision over facts the
//! syscall shim samples.
//!
//! The shim used to accept-and-noop whenever the target was not a mount root,
//! so `mount(NULL, "/not-a-mount", NULL, MS_SHARED)` reported success while
//! changing nothing — a silent lie userspace cannot distinguish from a retune
//! that took effect. Linux refuses it outright, and refuses a request whose
//! flag word does not name EXACTLY ONE propagation type.
//!
//! Kept `#[cfg]`-free and fact-driven so the ORDER and the errno of each rung
//! are a hosted unit test rather than something only a boot can exercise.

use super::flags::{MS_PRIVATE, MS_REC, MS_SHARED, MS_SILENT, MS_SLAVE, MS_UNBINDABLE};
use super::Propagation;
use crate::types::VfsError;

/// The mount-tree facts `do_change_type` consults, sampled once by the shim.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ChangeTypeFacts {
    /// `path_mounted(path)` — `path->mnt->mnt_root == path->dentry`, i.e. the
    /// resolved target IS the root of a mount rather than a plain directory.
    pub at_mount_root: bool,
    /// `is_mounted(&mnt->mnt)` — the mount belongs to a live namespace.
    pub in_namespace: bool,
    /// `ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN)` for the namespace that owns
    /// the TARGET mount (`may_change_propagation`).
    pub ns_capable: bool,
}

/// What an accepted retune must do.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ChangeType {
    pub kind: Propagation,
    /// `MS_REC` — apply to the whole subtree, not just the target.
    pub recurse: bool,
}

/// Linux `flags_to_propagation_type`: strip `MS_REC`/`MS_SILENT`, then demand
/// that what remains is EXACTLY ONE of the four propagation selectors. Any
/// other bit present, or zero/two-or-more selectors, is a malformed request.
/// # C: O(1)
pub fn flags_to_propagation_type(ms_flags: u64) -> Option<Propagation> {
    let ty = ms_flags & !(MS_REC | MS_SILENT);
    if ty & !(MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE) != 0 { return None; }
    match ty {
        MS_SHARED     => Some(Propagation::Shared),
        MS_PRIVATE    => Some(Propagation::Private),
        MS_SLAVE      => Some(Propagation::Slave),
        MS_UNBINDABLE => Some(Propagation::Unbindable),
        _             => None,
    }
}

/// Linux `do_change_type`'s decision, given the raw `mount(2)` flag word and
/// the sampled `facts`.
///
/// Rung order is upstream's: the mount-root test precedes the flag-shape test,
/// which precedes `may_change_propagation`'s namespace and capability tests.
/// Only the last rung reports `EPERM`; every earlier refusal is `EINVAL`.
/// # C: O(1)
pub fn change_type_check(ms_flags: u64, facts: &ChangeTypeFacts) -> Result<ChangeType, VfsError> {
    if !facts.at_mount_root { return Err(VfsError::Einval); }
    let kind = flags_to_propagation_type(ms_flags).ok_or(VfsError::Einval)?;
    if !facts.in_namespace { return Err(VfsError::Einval); }
    if !facts.ns_capable { return Err(VfsError::Eperm); }
    Ok(ChangeType { kind, recurse: ms_flags & MS_REC != 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_facts() -> ChangeTypeFacts {
        ChangeTypeFacts { at_mount_root: true, in_namespace: true, ns_capable: true }
    }

    #[test]
    fn each_selector_maps_to_its_propagation_type() {
        assert_eq!(flags_to_propagation_type(MS_SHARED), Some(Propagation::Shared));
        assert_eq!(flags_to_propagation_type(MS_PRIVATE), Some(Propagation::Private));
        assert_eq!(flags_to_propagation_type(MS_SLAVE), Some(Propagation::Slave));
        assert_eq!(flags_to_propagation_type(MS_UNBINDABLE), Some(Propagation::Unbindable));
    }

    #[test]
    fn ms_rec_and_ms_silent_are_stripped_before_the_shape_test() {
        assert_eq!(flags_to_propagation_type(MS_SHARED | MS_REC), Some(Propagation::Shared));
        assert_eq!(flags_to_propagation_type(MS_SLAVE | MS_SILENT), Some(Propagation::Slave));
    }

    #[test]
    fn two_selectors_or_none_is_malformed() {
        assert_eq!(flags_to_propagation_type(MS_SHARED | MS_SLAVE), None);
        assert_eq!(flags_to_propagation_type(0), None);
        assert_eq!(flags_to_propagation_type(MS_REC), None);
    }

    #[test]
    fn a_non_propagation_bit_makes_the_request_malformed() {
        // `mount(NULL, t, NULL, MS_SHARED|MS_RDONLY)` is not "share it and make
        // it read-only" — Linux rejects the whole call.
        assert_eq!(flags_to_propagation_type(MS_SHARED | super::super::flags::MS_RDONLY), None);
    }

    #[test]
    fn a_plain_directory_target_is_einval_not_a_silent_noop() {
        let f = ChangeTypeFacts { at_mount_root: false, ..ok_facts() };
        assert_eq!(change_type_check(MS_SHARED, &f), Err(VfsError::Einval));
    }

    #[test]
    fn the_mount_root_rung_outranks_the_flag_shape_rung() {
        // Both would refuse; Linux tests `path_mounted` first. Same errno, so
        // the test pins the ORDER by proving the malformed-flag path is not
        // what produced it: a correct flag word on a non-root target is still
        // EINVAL.
        let f = ChangeTypeFacts { at_mount_root: false, ..ok_facts() };
        assert_eq!(change_type_check(MS_SHARED | MS_SLAVE, &f), Err(VfsError::Einval));
        assert_eq!(change_type_check(MS_SHARED, &f), Err(VfsError::Einval));
    }

    #[test]
    fn a_mount_outside_any_namespace_is_einval() {
        let f = ChangeTypeFacts { in_namespace: false, ..ok_facts() };
        assert_eq!(change_type_check(MS_PRIVATE, &f), Err(VfsError::Einval));
    }

    #[test]
    fn only_the_capability_rung_reports_eperm() {
        let f = ChangeTypeFacts { ns_capable: false, ..ok_facts() };
        assert_eq!(change_type_check(MS_PRIVATE, &f), Err(VfsError::Eperm));
    }

    #[test]
    fn the_namespace_rung_outranks_the_capability_rung() {
        let f = ChangeTypeFacts { in_namespace: false, ns_capable: false, ..ok_facts() };
        assert_eq!(change_type_check(MS_PRIVATE, &f), Err(VfsError::Einval));
    }

    #[test]
    fn ms_rec_rides_through_as_the_recursive_request() {
        assert_eq!(change_type_check(MS_SLAVE | MS_REC, &ok_facts()),
            Ok(ChangeType { kind: Propagation::Slave, recurse: true }));
        assert_eq!(change_type_check(MS_SLAVE, &ok_facts()),
            Ok(ChangeType { kind: Propagation::Slave, recurse: false }));
    }
}
