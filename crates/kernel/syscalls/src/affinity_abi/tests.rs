// Hosted unit tests for the cpumask ABI + affinity decision core. The slot
// files are `#![cfg(target_os = "oxide-kernel")]`, so before this module the
// `len`-in-BYTES rules, the getaffinity return value glibc depends on, and the
// permission ordering were all unreachable from `cargo test`.
// Reference: Linux `kernel/sched/syscalls.c` (v7.2.0-rc4).

use super::*;

// --- cpumask sizing --------------------------------------------------------

/// `cpumask_size() == bitmap_size(nr_cpu_ids)`: 64 CPU ids is one 8-byte long.
#[test]
fn cpumask_size_matches_linux_bitmap_size() {
    assert_eq!(NR_CPU_IDS, 64);
    assert_eq!(CPUMASK_SIZE, 8);
    assert_eq!(CPUMASK_SIZE, ((NR_CPU_IDS + 7) / 8));
}

// --- sched_getaffinity: len rules + return value ---------------------------

/// `(len * 8) < nr_cpu_ids` is EINVAL. `len` is in BYTES, not bits and not
/// CPUs — a buffer that cannot hold the whole kernel mask is refused.
#[test]
fn getaffinity_rejects_a_buffer_too_small_for_the_kernel_mask() {
    for len in 0..8usize {
        assert_eq!(getaffinity_retlen(len), Err(Errno::Einval), "len={len} bytes < cpumask");
    }
    assert!(getaffinity_retlen(8).is_ok());
}

/// `len & (sizeof(unsigned long) - 1)` is EINVAL — the buffer must be a whole
/// number of longs.
#[test]
fn getaffinity_rejects_unaligned_len() {
    for len in [9usize, 10, 15, 17, 63, 127] {
        assert_eq!(getaffinity_retlen(len), Err(Errno::Einval), "len={len} not a multiple of 8");
    }
    for len in [8usize, 16, 24, 128, 1024] {
        assert!(getaffinity_retlen(len).is_ok(), "len={len} is a whole number of longs");
    }
}

/// The syscall returns `min(len, cpumask_size())` BYTES — never 0, never the
/// CPU count. glibc's `sched_getaffinity` zero-fills `cpuset[ret..cpusetsize]`
/// with it; returning 0 would leave the caller's `cpu_set_t` full of stale
/// bytes, and `__get_nprocs` would report the wrong CPU count.
#[test]
fn getaffinity_returns_bytes_written_not_zero() {
    assert_eq!(getaffinity_retlen(8), Ok(8));
    assert_eq!(getaffinity_retlen(16), Ok(8), "clamped to cpumask_size()");
    // glibc's default cpu_set_t is CPU_SETSIZE(1024) bits = 128 bytes.
    assert_eq!(getaffinity_retlen(128), Ok(8));
    assert_eq!(getaffinity_retlen(1024), Ok(8));
}

/// The reported mask is `p->cpus_mask & cpu_active_mask`: an offline CPU is
/// never advertised as usable, even though the stored mask still names it.
#[test]
fn getaffinity_masks_the_stored_mask_with_active_cpus() {
    assert_eq!(reported_mask(0b1111, 0b0011), 0b0011);
    assert_eq!(reported_mask(u64::MAX, 0b0001), 0b0001);
    assert_eq!(reported_mask(0b1000, 0b0011), 0, "pinned to an offline CPU reports empty");
}

// --- sched_setaffinity: user buffer decode ---------------------------------

/// The SET side has no minimum `len`: Linux clears the mask then copies
/// exactly `len` bytes. A 4-byte `cpu_set_t` names CPUs 0..31 and the rest read
/// as zero — rejecting it with EINVAL breaks those callers.
#[test]
fn setaffinity_accepts_a_short_len_and_zero_fills() {
    assert_eq!(set_copy_len(0), 0);
    assert_eq!(set_copy_len(1), 1);
    assert_eq!(set_copy_len(4), 4);
    assert_eq!(set_copy_len(8), 8);
    assert_eq!(set_copy_len(128), 8, "clamped to cpumask_size()");

    assert_eq!(mask_from_bytes(&[0b0000_0101]), 0b101, "one byte names CPUs 0..7");
    assert_eq!(mask_from_bytes(&[0xFF, 0xFF, 0xFF, 0xFF]), 0xFFFF_FFFF);
    assert_eq!(mask_from_bytes(&[]), 0, "len 0 copies nothing -> empty mask");
    assert_eq!(mask_from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0x80]), 1u64 << 63);
    // Bytes past cpumask_size() are never consulted.
    assert_eq!(mask_from_bytes(&[0xFF; 16]), u64::MAX);
}

/// The bytes are little-endian: bit N of byte K is CPU `K*8 + N`.
#[test]
fn mask_bytes_are_little_endian_cpu_order() {
    for cpu in 0..64usize {
        let mut b = [0u8; 8];
        b[cpu / 8] = 1u8 << (cpu % 8);
        assert_eq!(mask_from_bytes(&b), 1u64 << cpu, "cpu {cpu}");
    }
}

// --- sched_setaffinity: the ordered decision -------------------------------

const ALL: u64 = u64::MAX;
const ACTIVE: u64 = 0b1111;

/// The happy path stores the requested mask narrowed by the cpuset — NOT
/// narrowed by the active mask, so a CPU that is only temporarily offline stays
/// in the mask and is used again once it is back.
#[test]
fn setaffinity_stores_the_request_narrowed_by_the_cpuset_only() {
    assert_eq!(setaffinity_decide(0b1010, ALL, ACTIVE, false, true, false), Ok(0b1010));
    // A CPU outside the active set survives in the stored mask.
    assert_eq!(setaffinity_decide(0b1_0001, ALL, ACTIVE, false, true, false), Ok(0b1_0001));
    // The cpuset does narrow it.
    assert_eq!(setaffinity_decide(0b1111, 0b0011, ACTIVE, false, true, false), Ok(0b0011));
}

/// A mask that names no ACTIVE CPU is EINVAL: the task could never run again.
#[test]
fn setaffinity_rejects_a_mask_with_no_active_cpu() {
    assert_eq!(setaffinity_decide(0, ALL, ACTIVE, false, true, false), Err(Errno::Einval));
    assert_eq!(setaffinity_decide(0b1_0000, ALL, ACTIVE, false, true, false), Err(Errno::Einval));
    // Empty only after the cpuset intersection is still EINVAL.
    assert_eq!(setaffinity_decide(0b1100, 0b0011, ACTIVE, false, true, false), Err(Errno::Einval));
}

/// A task the caller does not own is EPERM unless the caller has CAP_SYS_NICE.
/// CAP_SYS_NICE is an OVERRIDE, not a precondition: an owner without it still
/// succeeds.
#[test]
fn setaffinity_requires_ownership_or_cap_sys_nice() {
    assert!(setaffinity_permitted(true, false));
    assert!(setaffinity_permitted(false, true));
    assert!(setaffinity_permitted(true, true));
    assert!(!setaffinity_permitted(false, false));

    assert_eq!(setaffinity_decide(0b1, ALL, ACTIVE, false, false, false), Err(Errno::Eperm));
    assert_eq!(setaffinity_decide(0b1, ALL, ACTIVE, false, false, true), Ok(0b1));
}

/// EPERM is decided BEFORE the mask is examined: an unprivileged caller
/// probing a foreign pid must not be able to tell an invalid mask from a
/// forbidden target.
#[test]
fn eperm_precedes_the_empty_mask_einval() {
    assert_eq!(setaffinity_decide(0, ALL, ACTIVE, false, false, false), Err(Errno::Eperm));
    assert_eq!(setaffinity_decide(0, ALL, ACTIVE, false, true, false), Err(Errno::Einval));
}

/// `PF_NO_SETAFFINITY` (per-CPU kernel threads such as `ksoftirqd/N`) is EINVAL,
/// and it is decided BEFORE the permission test — exactly Linux's order.
#[test]
fn per_cpu_kthreads_are_einval_before_any_permission_test() {
    assert_eq!(setaffinity_decide(0b1, ALL, ACTIVE, true, true, true), Err(Errno::Einval));
    assert_eq!(setaffinity_decide(0b1, ALL, ACTIVE, true, false, false), Err(Errno::Einval),
               "EINVAL wins over EPERM for a task that can never be repinned");
}

// --- cpuset composition ----------------------------------------------------

/// A cgroup `cpuset.cpus` write and a `sched_setaffinity(2)` call must compose,
/// not overwrite each other: the effective mask is their intersection, and the
/// user's own request is remembered so a later cpuset change re-applies it.
#[test]
fn cpuset_and_user_mask_compose_instead_of_last_writer_wins() {
    // No user request yet: the cpuset is the whole story.
    assert_eq!(cpuset_recompute(0b0011, 0), 0b0011);
    // User asked for CPUs 0..3, cpuset allows 0..1 -> 0..1.
    assert_eq!(cpuset_recompute(0b0011, 0b1111), 0b0011);
    // User asked for CPU 1 only, cpuset allows 0..1 -> CPU 1.
    assert_eq!(cpuset_recompute(0b0011, 0b0010), 0b0010);
    // Widening the cpuset re-admits the CPUs the user asked for.
    assert_eq!(cpuset_recompute(0b1111, 0b1010), 0b1010);
}

/// A cpuset disjoint from the user's request leaves the cpuset in force —
/// Linux never parks a task on an empty, unschedulable mask.
#[test]
fn a_disjoint_cpuset_wins_rather_than_emptying_the_mask() {
    assert_eq!(cpuset_recompute(0b1100, 0b0011), 0b1100);
    assert_ne!(cpuset_recompute(0b1100, 0b0011), 0);
}
