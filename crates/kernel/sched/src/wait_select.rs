// Linux wait child eligibility: pid form + thread-group parent scope +
// clone/non-clone selectors. Pure and hosted-tested so wait4/waitid share
// one contract instead of re-encoding filters in each queue.

use crate::signum::Signum;
use syscall::wait::{__WALL, __WCLONE, __WNOTHREAD};

#[derive(Copy, Clone)]
pub struct Waiter {
    pub tid:  u32,
    pub tgid: u32,
    pub pgid: u32,
}

#[derive(Copy, Clone)]
pub struct Candidate {
    /// Linux `real_parent` — the task that forked this one, and the owner of
    /// the `children` list `do_wait_thread` walks. `/proc/<pid>/status` PPid
    /// reports this, and it is what reparenting rewrites; a ptrace attach
    /// never touches it.
    pub parent_tid:  u32,
    pub parent_tgid: u32,
    /// Linux `parent` when it differs from `real_parent` — the tracer, and the
    /// owner of the `ptraced` list `ptrace_do_wait` walks. Zero when untraced.
    ///
    /// Derived from the ptrace link rather than stored as a second parent
    /// field: `__ptrace_link` sets `parent = tracer` and `__ptrace_unlink`
    /// restores `parent = real_parent`, which is exactly "the tracer if there
    /// is one". A stored copy could disagree with the link it mirrors.
    pub tracer_tid:  u32,
    pub tracer_tgid: u32,
    pub vpid:        u32,
    pub pgid:        u32,
    pub exit_signal: u8,
}

/// # C: O(1)
pub const fn pid_matches(c: Candidate, w: Waiter, pid: i32) -> bool {
    match pid {
        -1          => true,
        0           => c.pgid == w.pgid,
        p if p > 0  => c.vpid == p as u32,
        p           => c.pgid == (-p) as u32,
    }
}

/// # C: O(1)
pub const fn parent_scope_matches(c: Candidate, w: Waiter, options: u64) -> bool {
    if (options & __WNOTHREAD) != 0 {
        c.parent_tid == w.tid
    } else {
        c.parent_tid == w.tid || (c.parent_tid != 0 && c.parent_tgid == w.tgid)
    }
}

/// Linux `ptrace_do_wait`'s list membership, expressed as a predicate: the
/// waiter is the tracer, or — absent `__WNOTHREAD` — a thread of the tracer's
/// group, because `__do_wait` walks every thread's `ptraced` list.
/// # C: O(1)
pub const fn ptrace_scope_matches(c: Candidate, w: Waiter, options: u64) -> bool {
    if c.tracer_tid == 0 { return false; }
    if (options & __WNOTHREAD) != 0 {
        c.tracer_tid == w.tid
    } else {
        c.tracer_tid == w.tid || c.tracer_tgid == w.tgid
    }
}

/// # C: O(1)
pub const fn clone_selector_matches(c: Candidate, options: u64) -> bool {
    if (options & __WALL) != 0 { return true; }
    let clone_child = c.exit_signal != Signum::Sigchld as u8;
    if (options & __WCLONE) != 0 { clone_child } else { !clone_child }
}

/// Linux reaches a candidate through one of TWO lists, and `eligible_child`
/// then applies the pid form to both:
///
///   * `real_parent`'s `children` — the ordinary case, gated by the
///     `__WCLONE`/`__WALL` clone selector.
///   * the tracer's `ptraced` — `eligible_child`'s `if (ptrace || (wo_flags &
///     __WALL)) return 1;` skips the clone selector ENTIRELY for it. That is
///     load-bearing: a tracer attaches to threads and to `clone`d children
///     whose `exit_signal` is not SIGCHLD, and without the bypass a plain
///     `waitpid(-1)` in the tracer would never see any of their stops.
///
/// A tracee therefore stays visible to its real parent AND becomes visible to
/// its tracer, which is what makes `strace -p` on an unrelated pid work while
/// the shell that forked it keeps reaping it.
/// # C: O(1)
pub const fn eligible(c: Candidate, w: Waiter, pid: i32, options: u64) -> bool {
    if !pid_matches(c, w, pid) { return false; }
    if ptrace_scope_matches(c, w, options) { return true; }
    parent_scope_matches(c, w, options) && clone_selector_matches(c, options)
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Waiter = Waiter { tid: 100, tgid: 10, pgid: 70 };
    const C: Candidate = Candidate {
        parent_tid: 100, parent_tgid: 10, tracer_tid: 0, tracer_tgid: 0,
        vpid: 4242, pgid: 70, exit_signal: Signum::Sigchld as u8,
    };
    /// A tracee of `W` whose REAL parent is an unrelated process — the
    /// `strace -p <unrelated pid>` shape.
    const TRACED: Candidate = Candidate {
        parent_tid: 900, parent_tgid: 90, tracer_tid: 100, tracer_tgid: 10, ..C
    };

    #[test]
    fn pid_forms_match_linux_waitpid() {
        assert!(eligible(C, W, -1, 0));
        assert!(eligible(C, W, 0, 0));
        assert!(eligible(C, W, 4242, 0));
        assert!(eligible(C, W, -70, 0));
        assert!(!eligible(C, W, 70, 0));
        assert!(!eligible(C, W, -4242, 0));
    }

    #[test]
    fn default_wait_sees_sibling_thread_children() {
        let c = Candidate { parent_tid: 101, parent_tgid: 10, ..C };
        assert!(eligible(c, W, -1, 0));
        assert!(!eligible(c, W, -1, __WNOTHREAD));
    }

    #[test]
    fn clone_selectors_follow_exit_signal() {
        let clone = Candidate { exit_signal: 0, ..C };
        assert!(!eligible(clone, W, -1, 0));
        assert!(eligible(clone, W, -1, __WCLONE));
        assert!(eligible(clone, W, -1, __WALL));
        assert!(eligible(C, W, -1, 0));
        assert!(!eligible(C, W, -1, __WCLONE));
        assert!(eligible(C, W, -1, __WALL));
    }

    #[test]
    fn a_tracer_that_is_not_the_real_parent_can_still_wait_for_its_tracee() {
        // The whole point: before the ptrace link was consulted, this task was
        // invisible to its tracer's wait(), so every stop it reported could be
        // seen by nobody and the tracee stayed parked forever.
        assert!(eligible(TRACED, W, -1, 0));
        assert!(eligible(TRACED, W, 4242, 0));
        // The real parent keeps seeing it too — the two lists are independent.
        let real_parent = Waiter { tid: 900, tgid: 90, pgid: 70 };
        assert!(eligible(TRACED, real_parent, -1, 0));
    }

    #[test]
    fn an_unrelated_process_still_sees_neither_parent_link() {
        let stranger = Waiter { tid: 555, tgid: 55, pgid: 70 };
        assert!(!eligible(TRACED, stranger, -1, 0));
        assert!(!eligible(C, stranger, -1, 0));
    }

    #[test]
    fn a_ptrace_wait_bypasses_the_clone_selector() {
        // A tracer attaches to threads and to clone(2) children whose
        // exit_signal is not SIGCHLD; `eligible_child` returns 1 for the ptrace
        // list before the __WCLONE test, so a plain waitpid(-1) sees them.
        let thread = Candidate { exit_signal: 0, ..TRACED };
        assert!(eligible(thread, W, -1, 0));
        assert!(eligible(thread, W, -1, __WCLONE));
        assert!(eligible(thread, W, -1, __WALL));
        // Without the ptrace link the same candidate needs __WCLONE/__WALL.
        let untraced_thread = Candidate { tracer_tid: 0, tracer_tgid: 0, parent_tid: 100,
                                          parent_tgid: 10, exit_signal: 0, ..C };
        assert!(!eligible(untraced_thread, W, -1, 0));
        assert!(eligible(untraced_thread, W, -1, __WCLONE));
    }

    #[test]
    fn the_pid_form_still_applies_to_a_ptrace_wait() {
        assert!(!eligible(TRACED, W, 1, 0));
        assert!(!eligible(TRACED, W, -71, 0));
        assert!(eligible(TRACED, W, -70, 0));
    }

    #[test]
    fn wnothread_narrows_the_ptrace_list_to_the_calling_thread() {
        // A sibling thread of the tracer sees the tracee by default (Linux
        // walks every thread's ptraced list) but not under __WNOTHREAD.
        let sibling = Waiter { tid: 101, tgid: 10, pgid: 70 };
        assert!(eligible(TRACED, sibling, -1, 0));
        assert!(!eligible(TRACED, sibling, -1, __WNOTHREAD));
        assert!(eligible(TRACED, W, -1, __WNOTHREAD));
    }

    #[test]
    fn an_untraced_candidate_never_takes_the_ptrace_path() {
        // `tracer_tid == 0` means "no tracer" and must never alias a waiter
        // whose tid or tgid happens to be 0 into a ptrace match — the guard is
        // the explicit zero test, not the comparison.
        let zero = Waiter { tid: 0, tgid: 0, pgid: 70 };
        assert!(!ptrace_scope_matches(C, zero, 0));
        assert!(!ptrace_scope_matches(C, zero, __WNOTHREAD));
        assert!(!ptrace_scope_matches(C, W, 0));
        // ...and an untraced candidate reaches `eligible` only through the
        // real-parent arm, so the clone selector still gates it.
        let clone_child = Candidate { exit_signal: 0, ..C };
        assert!(!eligible(clone_child, W, -1, 0));
    }
}
