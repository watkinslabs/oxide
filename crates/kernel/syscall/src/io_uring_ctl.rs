// io_uring admission tunables — the live cells `io_uring_setup(2)` consults
// and `/proc/sys/kernel/{io_uring_disabled,io_uring_group}` read and write.
//
// They live here, below both procfs and the syscall layer, because both must
// see the SAME cell: a procfs-local copy would let an administrator disable
// io_uring in /proc while `io_uring_setup` kept handing out rings.
//
//   io_uring_disabled  0 = anyone may create a ring
//                      1 = only CAP_SYS_ADMIN or a member of io_uring_group
//                      2 = nobody (EPERM)
//   io_uring_group     gid whose members are exempt under 1; a negative value
//                      is "no group", which makes 1 equivalent to
//                      CAP_SYS_ADMIN-only.

use core::sync::atomic::{AtomicI32, Ordering};

/// `io_uring_disabled == 0`.
pub const DISABLED_OFF: i32 = 0;
/// `io_uring_disabled == 1` — privileged or group member only.
pub const DISABLED_PRIV: i32 = 1;
/// `io_uring_disabled == 2` — no ring may be created.
pub const DISABLED_ALL: i32 = 2;
/// Bounds procfs enforces on `io_uring_disabled` writes.
pub const DISABLED_BOUNDS: (i64, i64) = (DISABLED_OFF as i64, DISABLED_ALL as i64);
/// "No group set" — any negative gid.
pub const GROUP_NONE: i32 = -1;

static DISABLED: AtomicI32 = AtomicI32::new(DISABLED_OFF);
static GROUP: AtomicI32 = AtomicI32::new(GROUP_NONE);

/// Current `io_uring_disabled`. # C: O(1)
pub fn disabled() -> i32 { DISABLED.load(Ordering::Relaxed) }

/// Set `io_uring_disabled`. # C: O(1)
pub fn set_disabled(v: i32) { DISABLED.store(v, Ordering::Relaxed); }

/// Current `io_uring_group`; negative = unset. # C: O(1)
pub fn group() -> i32 { GROUP.load(Ordering::Relaxed) }

/// Set `io_uring_group`. # C: O(1)
pub fn set_group(v: i32) { GROUP.store(v, Ordering::Relaxed); }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunables_round_trip_and_default_to_permissive() {
        assert_eq!(DISABLED_BOUNDS, (0, 2));
        set_disabled(DISABLED_ALL);
        assert_eq!(disabled(), DISABLED_ALL);
        set_disabled(DISABLED_OFF);
        assert_eq!(disabled(), DISABLED_OFF);
        set_group(42);
        assert_eq!(group(), 42);
        set_group(GROUP_NONE);
        assert!(group() < 0);
    }
}
