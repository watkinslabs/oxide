// `prctl(PR_FUTEX_HASH, cmd, slots, 0)` — Linux `kernel/futex/core.c
// futex_hash_prctl`.
//
// The option asks the kernel to give THIS process a private futex hash table
// of `slots` buckets instead of sharing the global one, and to report how
// many buckets the private table currently has. It is a scalability knob, not
// a semantic one: a process without a private table behaves identically, just
// with more cross-process bucket contention.
//
// This port has ONE global futex hash and no per-mm table, which is the same
// shape as a Linux built without private futex hashing. In that build
// `futex_hash_allocate()` is `{ return -EINVAL; }` and
// `futex_hash_get_slots()` is `{ return 0; }`, so SET_SLOTS is EINVAL and
// GET_SLOTS reports zero buckets — "no private hash". Reporting a non-zero
// bucket count for the shared table instead would tell a caller its futexes
// are isolated when they are not.
//
// UNGATED: the sub-command ladder and the arg4 rule are hosted-testable.

use syscall::errno::Errno;

use super::uapi::*;

/// Bucket count reported for a process with no private futex hash.
const NO_PRIVATE_HASH_SLOTS: i64 = 0;

/// `futex_hash_prctl(arg2, arg3, arg4)`.
///
/// `PR_FUTEX_HASH_SET_SLOTS` checks arg4 BEFORE attempting the allocation, so
/// a non-zero arg4 is EINVAL regardless of the slot count. `GET_SLOTS` places
/// no restriction on arg3/arg4 at all — Linux reads neither.
/// # C: O(1)
pub fn decide(cmd: u64, _slots: u64, a4: u64) -> i64 {
    let err = |e: Errno| -(e.as_i32() as i64);
    match cmd {
        PR_FUTEX_HASH_SET_SLOTS => {
            if a4 != 0 { return err(Errno::Einval); }
            err(Errno::Einval)
        }
        PR_FUTEX_HASH_GET_SLOTS => NO_PRIVATE_HASH_SLOTS,
        _ => err(Errno::Einval),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EINVAL: i64 = -(Errno::Einval.as_i32() as i64);

    #[test]
    fn get_slots_reports_no_private_hash_and_ignores_the_tail_arguments() {
        assert_eq!(decide(PR_FUTEX_HASH_GET_SLOTS, 0, 0), 0);
        assert_eq!(decide(PR_FUTEX_HASH_GET_SLOTS, 4096, 7), 0,
                   "GET_SLOTS reads neither arg3 nor arg4");
    }

    #[test]
    fn set_slots_is_refused_without_a_private_hash() {
        for slots in [0, 1, 2, 4096, u64::MAX] {
            assert_eq!(decide(PR_FUTEX_HASH_SET_SLOTS, slots, 0), EINVAL);
        }
        assert_eq!(decide(PR_FUTEX_HASH_SET_SLOTS, 4096, 1), EINVAL,
                   "arg4 is validated before the allocation attempt");
    }

    #[test]
    fn unknown_sub_command_is_einval() {
        for cmd in [0, 3, 4, u64::MAX] {
            assert_eq!(decide(cmd, 0, 0), EINVAL);
        }
    }
}
