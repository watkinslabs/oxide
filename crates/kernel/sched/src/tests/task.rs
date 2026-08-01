use crate::jobctl::WakeKind;
use crate::task::{SchedClass, SchedPolicy, Task, TaskState};
use core::sync::atomic::Ordering;
use std::sync::{Arc, Barrier};
use std::vec::Vec;

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
fn concurrent_wakers_have_one_placement_owner() {
    const WAKERS: usize = 8;
    let task = Arc::new(Task::new(2, "wake-claim", SchedClass::Normal { weight: 1024 }));
    task.set_state(TaskState::Sleeping);
    let start = Arc::new(Barrier::new(WAKERS));
    let mut joins = Vec::new();
    for _ in 0..WAKERS {
        let task = Arc::clone(&task);
        let start = Arc::clone(&start);
        joins.push(std::thread::spawn(move || {
            start.wait();
            task.claim_wake()
        }));
    }
    let winners: usize = joins.into_iter().map(|j| usize::from(j.join().unwrap())).sum();
    assert_eq!(winners, 1, "only one waker may own runqueue placement");
    assert_eq!(task.state(), TaskState::Runnable);
}

#[test]
fn pending_wake_closes_current_task_state_check_race() {
    use crate::task::PendingWake;
    use crate::RunqueueInner;

    let prev = super::common::normal(3, 0, 1024);
    let next = super::common::normal(4, 1, 1024);
    let idle = super::common::idle(0);
    let mut rq = RunqueueInner::new(0, Arc::clone(&idle));
    prev.set_state(TaskState::Sleeping);
    prev.on_cpu.store(true, Ordering::Release);

    let observed = prev.state();
    assert_eq!(observed, TaskState::Sleeping, "schedule snapshots the parked state");
    assert!(prev.claim_wake(), "ttwu wins after schedule's stale state snapshot");
    let next_raw = Arc::as_ptr(&next) as *mut Task;
    assert_eq!(prev.pending_wake(next_raw), PendingWake::Defer,
        "the outgoing task cannot be queued before switch-off completes");
    assert_eq!(rq.nr_running(), 0);

    prev.on_cpu.store(false, Ordering::Release);
    assert_eq!(prev.pending_wake(next_raw), PendingWake::Ready);
    rq.enqueue(Arc::clone(&prev));
    assert_eq!(rq.nr_running(), 1);
    assert!(prev.on_rq.load(Ordering::Acquire));
    assert_eq!(prev.pending_wake(next_raw), PendingWake::Drop,
        "a stale wake-list copy must not duplicate the enqueue");
    rq.enqueue(Arc::clone(&prev));
    assert_eq!(rq.nr_running(), 1);
    assert!(Arc::ptr_eq(&rq.pick_next_task(), &prev));
    assert!(Arc::ptr_eq(&rq.pick_next_task(), &idle));
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
    assert_eq!(t.kernel_stack_bytes(), 0, "a task without an owned stack has no charge");
}

#[test]
fn kernel_stack_charge_extent_uses_owned_stack_not_arch_default() {
    let mut t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    // C213 replaced the caller-supplied Box stack with the guard-paged kstack
    // allocator, whose PMM frame hooks only exist in a booted kernel — so
    // `install_stack` cannot succeed here. The assertion below still owns its
    // case: no charge without a mounted cgroup, and none inferred from an
    // architecture stack default.
    // SAFETY: local unpublished task; no other stack reader exists.
    let installed = unsafe { t.install_stack() };
    assert!(!installed, "hosted build has no PMM frame hook, so no stack is owned");
    // No cgroup is mounted in this isolated unit test, so no accounting is
    // installed. This proves the owner does not infer a charged extent merely
    // from an architecture stack default.
    assert_eq!(t.kernel_stack_bytes(), 0);
}

#[test]
fn kernel_stack_snapshot_sums_task_owned_charge_only() {
    let before = crate::kernel_stack_bytes_snapshot();
    let task = Arc::new(Task::new(0x4b53_544b, "stack-accounting", SchedClass::Normal { weight: 1024 }));
    task.kernel_stack_charge_bytes.store(12345, Ordering::Release);
    crate::registry::insert(&task);
    assert_eq!(crate::kernel_stack_bytes_snapshot(), before + 12345);
    drop(task);
    assert_eq!(crate::kernel_stack_bytes_snapshot(), before);
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
fn mm_snapshot_pins_across_replacement() {
    let old = vmm::AddressSpace::new(0).expect("old mm");
    let new = vmm::AddressSpace::new(0).expect("new mm");
    let task = Task::new_user(12, "oom", SchedClass::Normal { weight: 1024 }, alloc::sync::Arc::clone(&old));
    let pinned = task.clone_mm().expect("mm pin");
    // SAFETY: hosted test is the task's sole scheduler mutator.
    unsafe { task.replace_mm(Some(alloc::sync::Arc::clone(&new))); }
    assert!(alloc::sync::Arc::ptr_eq(&pinned, &old));
    assert!(alloc::sync::Arc::ptr_eq(&task.clone_mm().expect("new mm pin"), &new));
}

/// `ru_maxrss` must survive the mm that earned it: `execve` and exit both
/// swap the address space away long before anything reads the peak back.
#[test]
fn a_departing_address_space_leaves_its_resident_peak_on_the_process() {
    let old = vmm::AddressSpace::new(0).expect("old mm");
    let uva = hal::UserVirtAddr::new(0x1_0000).expect("uva");
    old.mmap(Some(uva), 4096, vmm::VmaProt::READ | vmm::VmaProt::WRITE,
             vmm::VmaFlags::PRIVATE | vmm::VmaFlags::ANONYMOUS, vmm::VmaBacking::Anonymous, false)
        .expect("map one page");
    old.account_pte_install_at(uva);
    assert_eq!(old.accounting_snapshot().hiwater_rss_pages, 1);
    let task = Task::new_user(13, "exec", SchedClass::Normal { weight: 1024 }, alloc::sync::Arc::clone(&old));
    assert_eq!(task.thread_group.group_acct().hiwater_rss_pages(), 0);
    // SAFETY: hosted test is the task's sole scheduler mutator.
    unsafe { task.replace_mm(None); }
    assert_eq!(task.thread_group.group_acct().hiwater_rss_pages(), 1,
        "the peak has to outlive the mm or a reaped child reports ru_maxrss 0");
}

/// A kernel thread that borrows a user mm is not the owner of its pages, so
/// releasing the borrow must leave its own accounting untouched.
#[test]
fn releasing_a_borrowed_address_space_does_not_claim_its_peak() {
    let lent = vmm::AddressSpace::new(0).expect("lent mm");
    let uva = hal::UserVirtAddr::new(0x1_0000).expect("uva");
    lent.mmap(Some(uva), 4096, vmm::VmaProt::READ | vmm::VmaProt::WRITE,
              vmm::VmaFlags::PRIVATE | vmm::VmaFlags::ANONYMOUS, vmm::VmaBacking::Anonymous, false)
        .expect("map one page");
    lent.account_pte_install_at(uva);
    let kt = Task::new(14, "kworker", SchedClass::Normal { weight: 1024 });
    // SAFETY: hosted test is the task's sole scheduler mutator.
    unsafe { kt.replace_borrowed_mm(Some(alloc::sync::Arc::clone(&lent))); }
    // SAFETY: same.
    unsafe { kt.replace_borrowed_mm(None); }
    assert_eq!(kt.thread_group.group_acct().hiwater_rss_pages(), 0);
}

#[test]
fn task_pgid_and_sid_default_to_tid() {
    let t = Task::new(42, "t", SchedClass::Normal { weight: 1024 });
    assert_eq!(t.pgid(), 42);
    assert_eq!(t.sid(), 42);
}

#[test]
fn task_pgid_can_be_updated() {
    let t = Task::new(7, "t", SchedClass::Normal { weight: 1024 });
    t.set_pgid(99);
    assert_eq!(t.pgid(), 99);
    assert_eq!(t.sid(), 7);
}

#[test]
fn only_a_sigcont_wake_records_a_continue_event() {
    // Regression: every wake used to set `cont_pending`, so a `PTRACE_CONT`
    // raised a `wait4(WCONTINUED)` event the tracee never continued from.
    for (wake, expect) in [(WakeKind::Cont, true), (WakeKind::PtraceResume, false),
                           (WakeKind::Kill, false)] {
        let t = Task::new(31, "t", SchedClass::Normal { weight: 1024 });
        t.set_state(TaskState::Stopped);
        assert!(crate::registry::try_wake_stopped(&t, wake));
        assert_eq!(t.cont_pending.load(Ordering::Acquire), expect,
                   "{wake:?}");
        // The reason is published for the resuming task to read back.
        assert_eq!(crate::jobctl::wake_of(t.jobctl.load(Ordering::Acquire)), wake);
    }
}

#[test]
fn try_wake_stopped_flips_only_stopped_tasks() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    assert_eq!(t.state(), TaskState::Runnable);
    assert!(!crate::registry::try_wake_stopped(&t, WakeKind::Cont));
    assert_eq!(t.state(), TaskState::Runnable);
    t.set_state(TaskState::Stopped);
    assert!(crate::registry::try_wake_stopped(&t, WakeKind::Cont));
    assert_eq!(t.state(), TaskState::Runnable);
    assert!(!crate::registry::try_wake_stopped(&t, WakeKind::Cont));
}

#[test]
fn try_wake_stopped_ignores_zombie() {
    let t = Task::new(2, "t", SchedClass::Normal { weight: 1024 });
    t.set_state(TaskState::Zombie);
    assert!(!crate::registry::try_wake_stopped(&t, WakeKind::Cont));
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

#[test]
fn oom_score_adjustment_enforces_linux_abi_range() {
    let task = Task::new(4130, "oom", SchedClass::Normal { weight: 1024 });
    assert!(task.set_oom_score_adj(crate::oom::OOM_SCORE_ADJ_MIN));
    assert_eq!(task.oom_score_adj(), crate::oom::OOM_SCORE_ADJ_MIN);
    assert!(task.set_oom_score_adj(crate::oom::OOM_SCORE_ADJ_MAX));
    assert_eq!(task.oom_score_adj(), crate::oom::OOM_SCORE_ADJ_MAX);
    assert!(!task.set_oom_score_adj(crate::oom::OOM_SCORE_ADJ_MAX + 1));
    assert_eq!(task.oom_score_adj(), crate::oom::OOM_SCORE_ADJ_MAX);
}

#[test]
fn clone_fs_shares_owner_and_unshare_copies_it() {
    const PARENT_TID: u32 = 4_141;
    const CHILD_TID: u32 = 4_142;
    const TASK_WEIGHT: u32 = 1_024;
    let parent = Task::new(PARENT_TID, "fs-parent", SchedClass::Normal { weight: TASK_WEIGHT });
    let child = Task::new(CHILD_TID, "fs-child", SchedClass::Normal { weight: TASK_WEIGHT });

    child.inherit_fs_context_from(&parent, true);
    assert!(child.shares_fs_context_with(&parent), "CLONE_FS must retain one fs_struct owner");
    child.unshare_fs_context();
    assert!(!child.shares_fs_context_with(&parent), "unshare(CLONE_FS) must make a private fs_struct copy");
    assert_eq!(child.fs_context_snapshot().cwd(), parent.fs_context_snapshot().cwd());
    assert_eq!(child.fs_context_snapshot().root(), parent.fs_context_snapshot().root());
}

#[test]
fn fork_copies_fs_owner_without_clone_fs() {
    const PARENT_TID: u32 = 4_143;
    const CHILD_TID: u32 = 4_144;
    const TASK_WEIGHT: u32 = 1_024;
    let parent = Task::new(PARENT_TID, "fs-parent", SchedClass::Normal { weight: TASK_WEIGHT });
    let child = Task::new(CHILD_TID, "fs-child", SchedClass::Normal { weight: TASK_WEIGHT });

    child.inherit_fs_context_from(&parent, false);
    assert!(!child.shares_fs_context_with(&parent), "fork must copy rather than share fs_struct");
    assert_eq!(child.fs_context_snapshot().cwd(), parent.fs_context_snapshot().cwd());
    assert_eq!(child.fs_context_snapshot().root(), parent.fs_context_snapshot().root());
}

#[test]
fn parked_child_tid_write_is_claimed_exactly_once() {
    let t = Task::new(1, "t", SchedClass::Normal { weight: 1024 });
    // Nothing parked: every return to user mode asks and gets nothing.
    assert_eq!(t.take_set_child_tid(), None);
    t.vtid.store(4242, Ordering::Release);
    t.set_child_tid.store(0x7fff_0000, Ordering::Release);
    // The value published is the tid userspace sees, not the internal one.
    assert_eq!(t.take_set_child_tid(), Some((0x7fff_0000, 4242)));
    // A second return must not write again.
    assert_eq!(t.take_set_child_tid(), None);
    assert_eq!(t.set_child_tid.load(Ordering::Acquire), 0);
}
