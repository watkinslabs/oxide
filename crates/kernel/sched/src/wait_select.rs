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
    pub parent_tid:  u32,
    pub parent_tgid: u32,
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

/// # C: O(1)
pub const fn clone_selector_matches(c: Candidate, options: u64) -> bool {
    if (options & __WALL) != 0 { return true; }
    let clone_child = c.exit_signal != Signum::Sigchld as u8;
    if (options & __WCLONE) != 0 { clone_child } else { !clone_child }
}

/// # C: O(1)
pub const fn eligible(c: Candidate, w: Waiter, pid: i32, options: u64) -> bool {
    parent_scope_matches(c, w, options)
        && clone_selector_matches(c, options)
        && pid_matches(c, w, pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Waiter = Waiter { tid: 100, tgid: 10, pgid: 70 };
    const C: Candidate = Candidate {
        parent_tid: 100, parent_tgid: 10, vpid: 4242, pgid: 70,
        exit_signal: Signum::Sigchld as u8,
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
}
