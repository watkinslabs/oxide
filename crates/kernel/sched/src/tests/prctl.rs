// B1414: prctl(PR_SET_NAME/PR_GET_NAME/PR_SET_DUMPABLE/PR_GET_DUMPABLE)
// hosted coverage. `sys_set_name`/`sys_get_name`/`sys_set_dumpable` take
// `cur: &Task` directly (no `crate::live::current()` dependency), so they
// hosted-test without a live runqueue. User-pointer args are real local
// buffer addresses — always `< hal::USER_VA_END` on a hosted stack — so
// the actual `read_volatile`/`write_volatile` paths run for real, not a
// mock.

use super::common::registry_test_lock;
use crate::prctl::{sys_get_name, sys_set_dumpable, sys_set_name};
use crate::task::{SchedClass, Task, SUID_DUMP_DISABLE, SUID_DUMP_ROOT, SUID_DUMP_USER, TASK_COMM_LEN};
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use syscall::errno::Errno;
use syscall::SyscallArgs;

fn args1(a0: u64, a1: u64) -> SyscallArgs {
    SyscallArgs { a0, a1, a2: 0, a3: 0, a4: 0, a5: 0 }
}

fn get_name_into(t: &Task, buf: &mut [u8; TASK_COMM_LEN]) -> i64 {
    sys_get_name(t, &args1(0, buf.as_mut_ptr() as u64))
}

#[test]
fn name_round_trips_through_set_and_get() {
    let t = Task::new(1, "spawn", SchedClass::Normal { weight: 1024 });
    let input = b"worker\0\0\0\0\0\0\0\0\0";
    assert_eq!(sys_set_name(&t, &args1(0, input.as_ptr() as u64)), 0);
    assert_eq!(t.comm(), "worker");
    let mut out = [0xffu8; TASK_COMM_LEN];
    assert_eq!(get_name_into(&t, &mut out), 0);
    assert_eq!(&out[..6], b"worker");
    assert_eq!(out[6], 0, "PR_GET_NAME NUL-pads past the name like Linux");
}

#[test]
fn name_longer_than_task_comm_len_truncates_like_linux() {
    let t = Task::new(2, "spawn", SchedClass::Normal { weight: 1024 });
    // 20 bytes, no NUL within the first TASK_COMM_LEN-1=15 — Linux
    // `strncpy_from_user(comm, arg2, TASK_COMM_LEN - 1)` copies exactly
    // the first 15 and silently drops the rest.
    let input = b"abcdefghijklmnopqrst";
    assert_eq!(sys_set_name(&t, &args1(0, input.as_ptr() as u64)), 0);
    assert_eq!(t.comm(), "abcdefghijklmno", "truncated to TASK_COMM_LEN-1 bytes");
    let mut out = [0xffu8; TASK_COMM_LEN];
    assert_eq!(get_name_into(&t, &mut out), 0);
    assert_eq!(&out[..15], b"abcdefghijklmno");
    assert_eq!(out[15], 0, "buffer is NUL-padded, never overruns TASK_COMM_LEN");
}

#[test]
fn set_name_null_pointer_is_efault() {
    let t = Task::new(3, "spawn", SchedClass::Normal { weight: 1024 });
    let before = t.comm();
    let rc = sys_set_name(&t, &args1(0, 0));
    assert_eq!(rc, -(Errno::Efault.as_i32() as i64));
    assert_eq!(t.comm(), before, "a rejected SET must not mutate comm");
}

#[test]
fn set_name_kernel_half_pointer_is_efault() {
    let t = Task::new(4, "spawn", SchedClass::Normal { weight: 1024 });
    let rc = sys_set_name(&t, &args1(0, hal::USER_VA_END));
    assert_eq!(rc, -(Errno::Efault.as_i32() as i64));
}

#[test]
fn get_name_bad_pointer_is_efault() {
    let t = Task::new(5, "spawn", SchedClass::Normal { weight: 1024 });
    assert_eq!(sys_get_name(&t, &args1(0, 0)), -(Errno::Efault.as_i32() as i64));
    assert_eq!(sys_get_name(&t, &args1(0, u64::MAX)), -(Errno::Efault.as_i32() as i64));
}

#[test]
fn name_is_per_thread_not_shared() {
    let a = Task::new(6, "a-spawn", SchedClass::Normal { weight: 1024 });
    let b = Task::new(7, "b-spawn", SchedClass::Normal { weight: 1024 });
    let name_a = b"thread-a\0\0\0\0\0\0\0\0";
    assert_eq!(sys_set_name(&a, &args1(0, name_a.as_ptr() as u64)), 0);
    assert_eq!(a.comm(), "thread-a");
    assert_eq!(b.comm(), "b-spawn", "unrelated task's comm must be untouched");
}

#[test]
fn dumpable_round_trips_valid_values_and_defaults_to_user() {
    let t = Task::new(8, "spawn", SchedClass::Normal { weight: 1024 });
    assert_eq!(t.dumpable.load(Ordering::Acquire), SUID_DUMP_USER, "Linux default");
    for v in [SUID_DUMP_DISABLE, SUID_DUMP_USER, SUID_DUMP_ROOT] {
        assert_eq!(sys_set_dumpable(&t, &args1(0, v as u64)), 0);
        assert_eq!(t.dumpable.load(Ordering::Acquire), v);
    }
}

#[test]
fn dumpable_rejects_out_of_range_value_with_einval() {
    let t = Task::new(9, "spawn", SchedClass::Normal { weight: 1024 });
    sys_set_dumpable(&t, &args1(0, SUID_DUMP_ROOT as u64));
    let rc = sys_set_dumpable(&t, &args1(0, 3));
    assert_eq!(rc, -(Errno::Einval.as_i32() as i64));
    assert_eq!(t.dumpable.load(Ordering::Acquire), SUID_DUMP_ROOT, "rejected SET must not mutate state");
}

#[test]
fn registry_lookup_reflects_a_prctl_rename() {
    // Same lookup + `comm()` accessor procfs's pid_stat/pid_comm bodies use
    // (`sched::live::registry::lookup(tid)` re-exports this `crate::registry`),
    // so this proves /proc/<pid>/{comm,stat} observe the renamed thread
    // without duplicating procfs's own (differently-gated) test harness.
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let t = Arc::new(Task::new(4242, "before-rename", SchedClass::Normal { weight: 1024 }));
    crate::registry::insert(&t);
    let name = b"renamed\0\0\0\0\0\0\0\0\0";
    assert_eq!(sys_set_name(&t, &args1(0, name.as_ptr() as u64)), 0);
    let looked_up = crate::registry::lookup(4242).expect("tid 4242 should be live");
    assert_eq!(looked_up.comm(), "renamed");
}
