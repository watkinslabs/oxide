// `prctl(PR_SET_IO_FLUSHER / PR_GET_IO_FLUSHER)` — Linux `kernel/sys.c`.
//
// A userspace block-device server (nbd, iscsi, a FUSE daemon on the writeback
// path) sets this on itself so that its OWN allocations never recurse into
// reclaim that would issue IO back through it and deadlock. Linux implements
// it as `PF_MEMALLOC_NOIO | PF_LOCAL_THROTTLE` on the task.
//
// UNGATED: the permission-before-argument ordering is the whole contract and
// must be reachable from `cargo test`.

use core::sync::atomic::{AtomicBool, Ordering};

use syscall::errno::Errno;

/// Linux `PR_IO_FLUSHER` set/clear values for `arg2`.
const IO_FLUSHER_CLEAR: u64 = 0;
const IO_FLUSHER_SET:   u64 = 1;

/// `PR_SET_IO_FLUSHER`'s ladder.
///
/// The CAP_SYS_RESOURCE test runs BEFORE the tail-argument test and before
/// the value test, so an unprivileged caller that also passes garbage tail
/// arguments sees EPERM, not EINVAL. A port that validates first leaks the
/// argument shape to callers that are not allowed to use the option at all.
/// # C: O(1)
pub fn set_decide(has_cap: bool, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<bool, Errno> {
    if !has_cap { return Err(Errno::Eperm); }
    if a3 != 0 || a4 != 0 || a5 != 0 { return Err(Errno::Einval); }
    match a2 {
        IO_FLUSHER_SET => Ok(true),
        IO_FLUSHER_CLEAR => Ok(false),
        _ => Err(Errno::Einval),
    }
}

/// `PR_GET_IO_FLUSHER`'s ladder — same permission-first ordering, and arg2
/// must be zero here because it carries no value.
/// # C: O(1)
pub fn get_decide(has_cap: bool, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<(), Errno> {
    if !has_cap { return Err(Errno::Eperm); }
    if a2 != 0 || a3 != 0 || a4 != 0 || a5 != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Live per-task flag. Read by the page allocator's reclaim decision, which
/// is what makes the option mean something rather than round-trip: with it
/// set, an allocation from this task refuses to enter direct reclaim (which
/// descends pageout -> swap -> the block layer) and falls back to the
/// background reclaim wakeup instead.
#[derive(Debug)]
pub struct IoFlusher(AtomicBool);

impl Default for IoFlusher { fn default() -> Self { Self::new() } }

impl IoFlusher {
    /// # C: O(1)
    pub const fn new() -> Self { Self(AtomicBool::new(false)) }
    /// # C: O(1)
    pub fn get(&self) -> bool { self.0.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set(&self, on: bool) { self.0.store(on, Ordering::Release) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_precedes_argument_validation() {
        // Every shape an unprivileged caller can present is EPERM, including
        // the ones that would be EINVAL for a privileged caller.
        for args in [(0, 0, 0, 0), (1, 0, 0, 0), (2, 0, 0, 0), (0, 1, 1, 1), (u64::MAX, 9, 9, 9)] {
            assert_eq!(set_decide(false, args.0, args.1, args.2, args.3), Err(Errno::Eperm));
            assert_eq!(get_decide(false, args.0, args.1, args.2, args.3), Err(Errno::Eperm));
        }
    }

    #[test]
    fn set_accepts_only_zero_and_one() {
        assert_eq!(set_decide(true, 1, 0, 0, 0), Ok(true));
        assert_eq!(set_decide(true, 0, 0, 0, 0), Ok(false));
        for bad in [2, 3, u64::MAX] {
            assert_eq!(set_decide(true, bad, 0, 0, 0), Err(Errno::Einval));
        }
    }

    #[test]
    fn tail_arguments_must_be_zero() {
        for tail in [(1, 0, 0), (0, 1, 0), (0, 0, 1)] {
            assert_eq!(set_decide(true, 1, tail.0, tail.1, tail.2), Err(Errno::Einval));
        }
        assert_eq!(get_decide(true, 0, 0, 0, 0), Ok(()));
        for bad in [(1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)] {
            assert_eq!(get_decide(true, bad.0, bad.1, bad.2, bad.3), Err(Errno::Einval));
        }
    }

    #[test]
    fn live_flag_round_trips() {
        let f = IoFlusher::new();
        assert!(!f.get());
        f.set(true);
        assert!(f.get());
        f.set(false);
        assert!(!f.get());
    }
}
