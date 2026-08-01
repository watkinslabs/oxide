// Which pid numbers an accounting record carries, per target namespace.
//
// A record written to a container's accounting file must name the process by
// the container's own numbering; the same exit written to an intermediate
// ancestor's file must name it by THAT namespace's numbering, and the host's
// by the host's. Getting this wrong makes a container's log reference pids
// that never existed inside it — which is why the mapping is a pure function
// with its own tests rather than one field read at the exit site.
//
// UNGATED on purpose: a `#[cfg(test)]` block inside a kernel-gated file
// compiles away silently and reports success having built nothing.

use alloc::vec::Vec;

use fs::acct::NsTarget;

/// The initial pid namespace's id.
pub const INITIAL_PID_NS: u64 = 0;

/// One pid namespace's view of the exiting process: the namespace's id, and
/// the numbers that namespace gives the process and its real parent. A zero
/// number means that namespace does not name that task at all — the state a
/// container init's parent is in, seen from inside the container.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct NsView {
    pub ns_id: u64,
    pub pid:   u32,
    pub ppid:  u32,
}

/// One record target per namespace that numbers the exiting process, each
/// carrying that namespace's own numbering. # C: O(depth)
pub fn targets(views: &[NsView]) -> Vec<NsTarget> {
    views.iter()
        .filter(|view| view.pid != 0)
        .map(|view| NsTarget { ns_id: view.ns_id, pid: view.pid, ppid: view.ppid })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A three-deep nest: the container, an intermediate ancestor, and the
    /// host. Every level numbers the same exit differently.
    fn nested() -> [NsView; 3] {
        [
            NsView { ns_id: 42, pid: 7,   ppid: 1 },
            NsView { ns_id: 41, pid: 63,  ppid: 55 },
            NsView { ns_id: INITIAL_PID_NS, pid: 900, ppid: 880 },
        ]
    }

    /// One exit, three records, three numberings — the container-local pair
    /// inside, the host pair outside.
    #[test]
    fn each_namespace_is_told_its_own_numbering() {
        let t = targets(&nested());
        assert_eq!((t[0].ns_id, t[0].pid, t[0].ppid), (42, 7, 1));
        assert_eq!((t[2].ns_id, t[2].pid, t[2].ppid), (INITIAL_PID_NS, 900, 880));
    }

    /// An INTERMEDIATE ancestor namespace — neither the task's own nor the
    /// initial one — gets ITS OWN number for the process, not the host's.
    /// Reporting the global number here is the defect this numbering removes.
    #[test]
    fn an_intermediate_ancestor_gets_its_own_number() {
        let t = targets(&nested());
        assert_eq!((t[1].ns_id, t[1].pid, t[1].ppid), (41, 63, 55));
        assert_ne!(t[1].pid, t[2].pid);
        assert_ne!(t[1].pid, t[0].pid);
    }

    /// A task outside any container has exactly one view, the host's.
    #[test]
    fn a_task_outside_any_container_reports_its_global_pid() {
        let t = targets(&[NsView { ns_id: INITIAL_PID_NS, pid: 1234, ppid: 1 }]);
        assert_eq!(t.len(), 1);
        assert_eq!((t[0].pid, t[0].ppid), (1234, 1));
    }

    /// A container init's parent lives outside the container, so from inside
    /// there is no parent to name and `ac_ppid` is 0 — while the outer records
    /// for the same exit still name the real parent.
    #[test]
    fn a_parent_outside_the_namespace_is_invisible_from_inside_it() {
        let t = targets(&[
            NsView { ns_id: 42, pid: 1, ppid: 0 },
            NsView { ns_id: INITIAL_PID_NS, pid: 900, ppid: 880 },
        ]);
        assert_eq!((t[0].pid, t[0].ppid), (1, 0));
        assert_eq!(t[1].ppid, 880);
    }

    /// A namespace that does not number the process writes no record at all —
    /// a record whose `ac_pid` is 0 names no process.
    #[test]
    fn a_namespace_that_numbers_nothing_gets_no_record() {
        let t = targets(&[
            NsView { ns_id: 42, pid: 0, ppid: 0 },
            NsView { ns_id: INITIAL_PID_NS, pid: 900, ppid: 880 },
        ]);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].ns_id, INITIAL_PID_NS);
    }
}
