use crate::task::{SchedClass, SchedPolicy, Task, TaskState};
use core::sync::atomic::Ordering;

#[test]
fn cpus_allowed_defaults_to_any() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    assert_eq!(t.cpus_allowed.load(Ordering::Acquire), u64::MAX);
    t.cpus_allowed.store(1, Ordering::Release);
    assert_eq!(t.cpus_allowed.load(Ordering::Acquire) & (1 << 0), 1, "allowed on cpu0");
    assert_eq!(t.cpus_allowed.load(Ordering::Acquire) & (1 << 1), 0, "not on cpu1");
}

#[test]
fn load_weight_seeds_from_class() {
    let n = Task::new(1, "n", SchedClass::Normal { weight: 2048 });
    assert_eq!(n.load_weight.load(Ordering::Acquire), 2048);
    let r = Task::new(2, "r", SchedClass::Rt { prio: 50, policy: SchedPolicy::Fifo });
    assert_eq!(r.load_weight.load(Ordering::Acquire), crate::cputime::NICE_0_WEIGHT);
    n.load_weight.store(crate::cputime::nice_to_weight(-20), Ordering::Release);
    assert_eq!(n.load_weight.load(Ordering::Acquire), 88761);
}

#[test]
fn task_cas_state_transitions() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    assert_eq!(t.state(), TaskState::Runnable);
    t.cas_state(TaskState::Runnable, TaskState::Sleeping).unwrap();
    assert_eq!(t.state(), TaskState::Sleeping);
    let err = t.cas_state(TaskState::Runnable, TaskState::Zombie).unwrap_err();
    assert_eq!(err, TaskState::Sleeping);
    assert_eq!(t.state(), TaskState::Sleeping);
    t.cas_state(TaskState::Sleeping, TaskState::Runnable).unwrap();
    assert_eq!(t.state(), TaskState::Runnable);
}

#[test]
fn task_lift_vruntime_respects_floor() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    t.vruntime.store(50, Ordering::Release);
    t.lift_vruntime(100);
    assert_eq!(t.vruntime.load(Ordering::Acquire), 100);
    t.lift_vruntime(20);
    assert_eq!(t.vruntime.load(Ordering::Acquire), 100);
}

#[test]
fn task_kernel_stack_starts_null() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    assert!(t.kernel_stack.load(Ordering::Acquire).is_null());
}

#[test]
fn task_arch_ctx_buffer_is_zero_initialised() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    // SAFETY: hosted test; we are the sole accessor of `t.arch_ctx`.
    let buf = unsafe { &*t.arch_ctx.get() };
    assert!(buf.0.iter().all(|&b| b == 0));
    assert_eq!(buf.0.len(), crate::ARCH_CTX_SIZE);
}

#[test]
fn task_arch_ctx_ptr_round_trips() {
    #[repr(C)]
    struct FakeCtx { rsp: u64, marker: u64 }
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    // SAFETY: hosted test; we are the sole accessor of `t.arch_ctx`; FakeCtx fits ARCH_CTX_SIZE.
    unsafe {
        let p = t.arch_ctx_ptr::<FakeCtx>();
        (*p).rsp = 0xdead_b000_dead_b000;
        (*p).marker = 0xfeedface;
    }
    // SAFETY: hosted test; sole accessor; reading the same storage.
    let buf = unsafe { &*t.arch_ctx.get() };
    let rsp = u64::from_ne_bytes(buf.0[0..8].try_into().unwrap());
    let marker = u64::from_ne_bytes(buf.0[8..16].try_into().unwrap());
    assert_eq!(rsp, 0xdead_b000_dead_b000);
    assert_eq!(marker, 0xfeedface);
}

#[test]
fn task_kthread_has_no_mm() {
    let t = Task::new(1, "kt", SchedClass::Normal { weight: 1024 });
    // SAFETY: hosted test; single-threaded.
    assert!(unsafe { t.mm_ref() }.is_none(), "kthread Task must not carry an mm");
}

#[test]
fn task_user_carries_mm() {
    let mm = vmm::AddressSpace::new(0).expect("AddressSpace::new should succeed");
    let t1 = Task::new_user(10, "u1", SchedClass::Normal { weight: 1024 }, alloc::sync::Arc::clone(&mm));
    let t2 = Task::new_user(11, "u2", SchedClass::Normal { weight: 1024 }, alloc::sync::Arc::clone(&mm));
    // SAFETY: hosted test; single-threaded; no concurrent writer.
    let m1 = unsafe { t1.mm_ref() }.expect("u1 mm");
    // SAFETY: same as above.
    let m2 = unsafe { t2.mm_ref() }.expect("u2 mm");
    assert!(alloc::sync::Arc::ptr_eq(m1, m2), "CLONE_VM siblings must share the same AS instance");
    assert_eq!(alloc::sync::Arc::strong_count(&mm), 3);
}

#[test]
fn task_pgid_and_sid_default_to_tid() {
    let t = Task::new(42, "t", SchedClass::Normal { weight: 1024 });
    assert_eq!(t.pgid.load(Ordering::Acquire), 42);
    assert_eq!(t.sid.load(Ordering::Acquire), 42);
}

#[test]
fn task_pgid_can_be_updated() {
    let t = Task::new(7, "t", SchedClass::Normal { weight: 1024 });
    t.pgid.store(99, Ordering::Release);
    assert_eq!(t.pgid.load(Ordering::Acquire), 99);
    assert_eq!(t.sid.load(Ordering::Acquire), 7);
}

#[test]
fn try_wake_stopped_flips_only_stopped_tasks() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    assert_eq!(t.state(), TaskState::Runnable);
    assert!(!crate::registry::try_wake_stopped(&t));
    assert_eq!(t.state(), TaskState::Runnable);
    t.set_state(TaskState::Stopped);
    assert!(crate::registry::try_wake_stopped(&t));
    assert_eq!(t.state(), TaskState::Runnable);
    assert!(!crate::registry::try_wake_stopped(&t));
}

#[test]
fn try_wake_stopped_ignores_zombie() {
    let t = Task::new(2, "t", SchedClass::Normal { weight: 1024 });
    t.set_state(TaskState::Zombie);
    assert!(!crate::registry::try_wake_stopped(&t));
    assert_eq!(t.state(), TaskState::Zombie);
}

#[test]
fn task_state_linux_char() {
    assert_eq!(TaskState::Runnable.linux_char(), b'R');
    assert_eq!(TaskState::Sleeping.linux_char(), b'S');
    assert_eq!(TaskState::Stopped.linux_char(), b'T');
    assert_eq!(TaskState::Zombie.linux_char(), b'Z');
}

#[test]
fn task_state_linux_status_label() {
    assert_eq!(TaskState::Runnable.linux_status_label(), "R (running)");
    assert_eq!(TaskState::Stopped.linux_status_label(), "T (stopped)");
    assert_eq!(TaskState::Zombie.linux_status_label(), "Z (zombie)");
}

#[test]
fn visible_pid_prefers_vtgid_then_falls_back_to_tgid() {
    let t = Task::new(4120, "svc", SchedClass::Normal { weight: 1024 });
    t.tgid.store(4120, Ordering::Release);
    t.vtgid.store(0, Ordering::Release);
    assert_eq!(t.visible_pid(), 4120);
    t.vtgid.store(40, Ordering::Release);
    assert_eq!(t.visible_pid(), 40);
}
