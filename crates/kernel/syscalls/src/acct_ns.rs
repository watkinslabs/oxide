// Which pid numbers an accounting record carries, per target namespace.
//
// A record written to a container's accounting file must name the process by
// the container's own numbering; the same exit written to the host's file must
// name it by the host's. Getting this wrong makes a container's log reference
// pids that never existed inside it — which is why the mapping is a pure
// function with its own tests rather than one field read at the exit site.
//
// UNGATED on purpose: a `#[cfg(test)]` block inside a kernel-gated file
// compiles away silently and reports success having built nothing.

use fs::acct::NsTarget;

/// The two pid views this kernel materialises for a task: the initial pid
/// namespace's numbering, and the task's own namespace's numbering.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct NsPids {
    /// The task's own pid namespace id. Zero is the initial namespace.
    pub own_ns:      u64,
    /// Thread-group id in the INITIAL pid namespace.
    pub global_pid:  u32,
    /// Thread-group id in `own_ns`. Zero when the task has no distinct
    /// namespace-local number, i.e. it lives in the initial namespace.
    pub own_pid:     u32,
    /// Real parent's thread-group id in the INITIAL pid namespace.
    pub global_ppid: u32,
    /// Real parent's thread-group id in `own_ns`; zero when the parent is
    /// outside that namespace and therefore invisible from inside it.
    pub own_ppid:    u32,
}

/// The initial pid namespace's id.
pub const INITIAL_PID_NS: u64 = 0;

impl NsPids {
    /// The record destined for `ns_id`. A target that IS the task's own
    /// namespace gets the namespace-local numbers; every ancestor — including
    /// the initial namespace — gets the global ones, because an ancestor can
    /// see the task and numbers it from the outside. A task that is not in a
    /// distinct namespace has no local number, so the global one stands
    /// everywhere. # C: O(1)
    pub fn target_for(&self, ns_id: u64) -> NsTarget {
        let local = ns_id == self.own_ns && ns_id != INITIAL_PID_NS && self.own_pid != 0;
        if local {
            NsTarget { ns_id, pid: self.own_pid, ppid: self.own_ppid }
        } else {
            NsTarget { ns_id, pid: self.global_pid, ppid: self.global_ppid }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nested() -> NsPids {
        NsPids {
            own_ns: 42,
            global_pid: 900, own_pid: 7,
            global_ppid: 880, own_ppid: 1,
        }
    }

    /// A containerised process's own namespace sees its container-local pid
    /// pair; the host namespace sees the host pair. One exit, two records, two
    /// numberings.
    #[test]
    fn each_namespace_is_told_its_own_numbering() {
        let p = nested();
        let inner = p.target_for(42);
        assert_eq!((inner.pid, inner.ppid), (7, 1));
        let host = p.target_for(INITIAL_PID_NS);
        assert_eq!((host.pid, host.ppid), (900, 880));
        // The target carries the namespace it was built for, so the writer
        // cannot deliver a record to the wrong file.
        assert_eq!((inner.ns_id, host.ns_id), (42, 0));
    }

    /// An INTERMEDIATE ancestor namespace — one that is neither the task's own
    /// nor the initial one — sees the task from outside, so it gets the global
    /// numbering rather than the task's namespace-local pid.
    #[test]
    fn an_ancestor_namespace_never_gets_the_tasks_local_pid() {
        let t = nested().target_for(41);
        assert_eq!((t.pid, t.ppid), (900, 880));
    }

    /// A task in the initial namespace has one numbering, and it is the global
    /// one — never the zero its unused namespace-local slot holds.
    #[test]
    fn a_task_outside_any_container_reports_its_global_pid() {
        let p = NsPids {
            own_ns: INITIAL_PID_NS,
            global_pid: 1234, own_pid: 0,
            global_ppid: 1, own_ppid: 0,
        };
        let t = p.target_for(INITIAL_PID_NS);
        assert_eq!((t.pid, t.ppid), (1234, 1));
    }

    /// A namespace id that matches but with no local number recorded falls
    /// back to the global pair rather than writing a zero pid — a record whose
    /// `ac_pid` is 0 names no process at all.
    #[test]
    fn a_missing_local_number_falls_back_rather_than_writing_zero() {
        let p = NsPids { own_ns: 42, global_pid: 900, own_pid: 0, global_ppid: 880, own_ppid: 0 };
        let t = p.target_for(42);
        assert_eq!((t.pid, t.ppid), (900, 880));
    }

    /// A container init's parent lives outside the container, so from inside
    /// there is no parent to name and `ac_ppid` is 0 — while the host's record
    /// for the same exit still names the real parent.
    #[test]
    fn a_parent_outside_the_namespace_is_invisible_from_inside_it() {
        let p = NsPids { own_ns: 42, global_pid: 900, own_pid: 1, global_ppid: 880, own_ppid: 0 };
        assert_eq!((p.target_for(42).pid, p.target_for(42).ppid), (1, 0));
        assert_eq!(p.target_for(INITIAL_PID_NS).ppid, 880);
    }
}
