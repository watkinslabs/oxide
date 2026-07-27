// docs/15 §2 OBSOLETE syscall numbers — the slots modern Linux x86_64 itself
// answers with ENOSYS.
//
// Deliberately NOT kernel-cfg'd. This lived in `misc.rs`, which is
// `#![cfg(target_os = "oxide-kernel")]`, so any test of it silently compiled
// out — and the set had in fact drifted from Linux's table without anything
// noticing.

use syscall::nrs::*;

/// The OBSOLETE set, in numeric order: exactly the rows of Linux
/// `arch/x86/entry/syscalls/syscall_64.tbl` carrying no entry point or
/// `sys_ni_syscall`.
pub const OBSOLETE_NRS: [u64; 17] = [
    NR_USELIB, NR__SYSCTL, NR_CREATE_MODULE, NR_GET_KERNEL_SYMS,
    NR_QUERY_MODULE, NR_NFSSERVCTL, NR_GETPMSG, NR_PUTPMSG, NR_AFS_SYSCALL,
    NR_TUXCALL, NR_SECURITY, NR_SET_THREAD_AREA, NR_GET_THREAD_AREA,
    NR_LOOKUP_DCOOKIE, NR_EPOLL_CTL_OLD, NR_EPOLL_WAIT_OLD, NR_VSERVER,
];

/// True for a slot Linux itself leaves unimplemented, so our ENOSYS is a
/// deliberate match rather than the accidental dispatch fall-through.
///
/// Four members (uselib, _sysctl, lookup_dcookie, vserver) used to be absent
/// from the predicate and reached ENOSYS only by falling off the end of
/// dispatch — the precise accident this exists to rule out, and from the
/// caller's side indistinguishable from a slot we simply never implemented.
/// # C: O(17)
pub fn is_obsolete(nr: u64) -> bool { OBSOLETE_NRS.contains(&nr) }

#[cfg(test)]
mod tests {
    use super::*;

    /// The set is not a judgement call — it is Linux's table. Pinning the
    /// literal numbers means an edit that drops one, or that "helpfully" adds
    /// a slot Linux does implement, fails here instead of silently ENOSYS-ing
    /// a real syscall.
    #[test]
    fn obsolete_set_matches_linux() {
        let linux: [u64; 17] = [
            134, // uselib
            156, // _sysctl          (sys_ni_syscall)
            174, // create_module
            177, // get_kernel_syms
            178, // query_module
            180, // nfsservctl
            181, // getpmsg
            182, // putpmsg
            183, // afs_syscall
            184, // tuxcall
            185, // security
            205, // set_thread_area
            211, // get_thread_area
            212, // lookup_dcookie
            214, // epoll_ctl_old
            215, // epoll_wait_old
            236, // vserver
        ];
        let mut ours = OBSOLETE_NRS;
        ours.sort_unstable();
        assert_eq!(ours, linux, "OBSOLETE set drifted from Linux syscall_64.tbl");
    }

    #[test]
    fn every_obsolete_nr_is_reported_obsolete() {
        for nr in OBSOLETE_NRS { assert!(is_obsolete(nr), "nr {nr} missing from is_obsolete"); }
    }

    /// Guard the other direction: slots we really implement must never be
    /// swept into the ENOSYS path. read/write/futex/openat/clone3 are the ones
    /// whose loss would be catastrophic and silent.
    #[test]
    fn implemented_slots_are_not_obsolete() {
        for nr in [NR_READ, NR_WRITE, NR_FUTEX, NR_OPENAT, NR_CLONE3] {
            assert!(!is_obsolete(nr), "nr {nr} must not be treated as obsolete");
        }
    }
}
