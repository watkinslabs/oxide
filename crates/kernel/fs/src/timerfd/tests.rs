use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use syscall::errno::Errno;

use super::*;

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static CURRENT: AtomicPtr<sched::Task> = AtomicPtr::new(ptr::null_mut());

fn hooked_current() -> Option<&'static sched::Task> {
    let task = CURRENT.load(Ordering::Acquire);
    if task.is_null() {
        None
    } else {
        // SAFETY: fixtures store only leaked tasks and retain them for the process lifetime.
        Some(unsafe { &*task })
    }
}

fn reset_current() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
}

struct Fixture {
    task:  &'static sched::Task,
    table: Arc<vfs::FdTable>,
    inode: InodeRef,
    fd:    i32,
}

impl Fixture {
    fn new(clockid: u64) -> Self {
        let task = Box::leak(Box::new(sched::Task::new(
            0x1556,
            "timerfd-test",
            sched::SchedClass::Normal { weight: 1024 },
        )));
        let table = Arc::new(vfs::FdTable::new());
        // SAFETY: the leaked hosted task is unscheduled and this fixture is its sole writer.
        unsafe { task.replace_fd_table(Some(Arc::clone(&table))); }
        let inode = make_timerfd_inode(clockid);
        let dentry = vfs::Dentry::new_root(Arc::clone(&inode));
        let file = vfs::File::new(Arc::clone(&inode), dentry, vfs::OpenFlags::O_RDONLY);
        let fd = table.alloc(file).unwrap();
        CURRENT.store(task as *const sched::Task as *mut sched::Task, Ordering::Release);
        sched::set_current_hook(hooked_current);
        Self { task, table, inode, fd }
    }

    fn data(&self) -> &TimerfdData {
        self.inode.private::<TimerfdData>().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) { reset_current(); }
}

fn neg(errno: Errno) -> i64 { -(errno.as_i32() as i64) }

fn wire(interval_sec: i64, interval_nsec: i64, value_sec: i64, value_nsec: i64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (slot, value) in [interval_sec, interval_nsec, value_sec, value_nsec].iter().enumerate() {
        bytes[slot * 8..slot * 8 + 8].copy_from_slice(&value.to_ne_bytes());
    }
    bytes
}

#[test]
fn absolute_namespace_clock_routes_only_linux_virtualized_clocks() {
    assert_eq!(timerfd_namespace_clock(CLOCK_MONOTONIC),
        Some(nscg::time_ns::TimeNsClock::Monotonic));
    assert_eq!(timerfd_namespace_clock(CLOCK_BOOTTIME),
        Some(nscg::time_ns::TimeNsClock::Boottime));
    assert_eq!(timerfd_namespace_clock(CLOCK_BOOTTIME_ALARM),
        Some(nscg::time_ns::TimeNsClock::Boottime));
    assert_eq!(timerfd_namespace_clock(CLOCK_REALTIME), None);
    assert_eq!(timerfd_namespace_clock(CLOCK_REALTIME_ALARM), None);
}

#[test]
fn deadline_maps_relative_and_realtime_values_to_host_monotonic() {
    assert_eq!(monotonic_deadline_from_value(0, 7, 11), 18);
    assert_eq!(monotonic_deadline_from_value(TFD_TIMER_ABSTIME, 7, 11), 7);
    assert_eq!(realtime_deadline(25, 11, 18), 18);
    assert_eq!(realtime_deadline(17, 11, 18), 11);

    let now_mono = 1_000_000_000;
    let now_real = 1_774_000_000_000_000_000;
    let huge = syscall::time::timespec_to_ns(16_661_643_624, 155_194_468).unwrap();
    assert_eq!(huge, syscall::time::KTIME_MAX_NS);
    assert_eq!(realtime_deadline(huge, now_mono, now_real),
        now_mono + (syscall::time::KTIME_MAX_NS - now_real));
}

fn settime_args(fd: i32, flags: u64, new: &[u8; 32], old: u64) -> syscall::SyscallArgs {
    syscall::SyscallArgs {
        a0: fd as u64,
        a1: flags,
        a2: new.as_ptr() as u64,
        a3: old,
        ..Default::default()
    }
}

#[test]
fn settime_imports_new_then_validates_flags_and_value_before_fd_lookup() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    reset_current();
    let null_new = syscall::SyscallArgs {
        a0: u64::MAX, a1: u64::MAX, a2: 0, ..Default::default()
    };
    assert_eq!(sys_timerfd_settime(&null_new), neg(Errno::Efault));

    let valid = wire(0, 0, 1, 0);
    assert_eq!(sys_timerfd_settime(&settime_args(-1, 4, &valid, 0)), neg(Errno::Einval));
    let invalid = wire(0, 0, -1, 0);
    assert_eq!(sys_timerfd_settime(&settime_args(-1, 0, &invalid, 0)), neg(Errno::Einval));
    assert_eq!(sys_timerfd_settime(&settime_args(-1, 0, &valid, 0)), neg(Errno::Ebadf));
    assert_eq!(sys_timerfd_settime(
        &settime_args(-1, (1u64 << 32) | TFD_TIMER_ABSTIME, &valid, 0),
    ), neg(Errno::Ebadf));
}

#[test]
fn create_validates_clock_and_flags_before_alarm_capability() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    reset_current();
    let invalid_flags = syscall::SyscallArgs {
        a0: CLOCK_REALTIME_ALARM,
        a1: 1,
        ..Default::default()
    };
    assert_eq!(sys_timerfd_create(&invalid_flags), neg(Errno::Einval));
    let valid_alarm = syscall::SyscallArgs {
        a0: CLOCK_REALTIME_ALARM,
        ..Default::default()
    };
    assert_eq!(sys_timerfd_create(&valid_alarm), neg(Errno::Eperm));
    let high_word_only = syscall::SyscallArgs {
        a0: CLOCK_MONOTONIC,
        a1: 1u64 << 32,
        ..Default::default()
    };
    assert_eq!(sys_timerfd_create(&high_word_only), neg(Errno::Ebadf));
}

#[test]
fn create_uses_rdwr_and_timerfd_write_is_einval() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new(CLOCK_MONOTONIC);
    let args = syscall::SyscallArgs {
        a0: CLOCK_MONOTONIC,
        ..Default::default()
    };
    let fd = sys_timerfd_create(&args);
    assert!(fd >= 0);
    let file = fixture.table.get(fd as i32).unwrap();
    assert!(file.flags().contains(vfs::OpenFlags::O_RDWR));
    assert_eq!(TimerfdFileOps.write(&file.inode(), 0, &[1]), Err(VfsError::Einval));
}

#[test]
fn invalid_new_leaves_old_output_and_timer_state_untouched() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new(CLOCK_MONOTONIC);
    let initial = TimerfdState {
        expiry_ns: u64::MAX,
        interval_ns: 25,
        ticks: 7,
        clock_generation_seen: 9,
        cancel_enabled: true,
        cancel_pending: false,
        realtime_absolute: false, settime_flags: 0,
        realtime_projection_ns: 0,
    };
    *fixture.data().state.lock() = initial;
    let invalid = wire(0, 0, -1, 0);
    let mut old = [0x5au8; 32];
    let args = settime_args(fixture.fd, 0, &invalid, old.as_mut_ptr() as u64);
    assert_eq!(sys_timerfd_settime(&args), neg(Errno::Einval));
    assert_eq!(old, [0x5a; 32]);
    assert_eq!(*fixture.data().state.lock(), initial);
}

#[test]
fn failed_old_copyout_leaves_new_timer_installed() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new(CLOCK_MONOTONIC);
    let valid = wire(2, 0, 5, 0);
    let args = settime_args(fixture.fd, 0, &valid, hal::USER_VA_END);
    assert_eq!(sys_timerfd_settime(&args), neg(Errno::Efault));
    let state = *fixture.data().state.lock();
    assert_eq!(state.interval_ns, 2_000_000_000);
    assert!(state.expiry_ns > monotonic_ns());
    assert_eq!(state.ticks, 0);
    assert!(!state.cancel_enabled);
}

#[test]
fn successful_old_copyout_uses_native_itimerspec_layout() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new(CLOCK_MONOTONIC);
    *fixture.data().state.lock() = TimerfdState {
        expiry_ns: 3_500_000_000,
        interval_ns: 2_250_000_000,
        ..TimerfdState::new(0)
    };
    let new = wire(0, 0, 5, 0);
    let mut old = [0u8; 32];
    assert_eq!(sys_timerfd_settime(&settime_args(
        fixture.fd, 0, &new, old.as_mut_ptr() as u64,
    )), 0);
    let field = |offset| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&old[offset..offset + 8]);
        i64::from_ne_bytes(bytes)
    };
    assert_eq!([field(0), field(8), field(16), field(24)],
        [2, 250_000_000, 3, 500_000_000]);
}

#[test]
fn alarm_capability_is_rechecked_after_input_and_fd_validation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new(CLOCK_REALTIME_ALARM);
    fixture.task.creds.cap_effective.fetch_and(
        !(1u64 << sched::cap::WAKE_ALARM),
        Ordering::AcqRel,
    );
    let initial = *fixture.data().state.lock();
    let valid = wire(0, 0, 5, 0);
    let mut old = [0xa5u8; 32];
    assert_eq!(sys_timerfd_settime(&settime_args(
        fixture.fd, 0, &valid, old.as_mut_ptr() as u64,
    )), neg(Errno::Eperm));
    assert_eq!(*fixture.data().state.lock(), initial);
    assert_eq!(old, [0xa5; 32]);

    let invalid = wire(0, 0, -1, 0);
    assert_eq!(sys_timerfd_settime(&settime_args(fixture.fd, 0, &invalid, 0)),
        neg(Errno::Einval));
}

#[test]
fn expired_periodic_snapshot_advances_phase_and_preserves_missed_ticks() {
    let mut state = TimerfdState {
        expiry_ns: 10,
        interval_ns: 10,
        ..TimerfdState::disarmed()
    };
    let snapshot = state.snapshot(35, 0);
    assert_eq!(snapshot, uapi::Itimerspec { interval_ns: 10, value_ns: 5 });
    assert_eq!(state.expiry_ns, 40);
    assert_eq!(state.ticks, 3);
    let mut output = [0u8; 8];
    assert_eq!(timerfd_take_expirations(&mut state, 35, 0, &mut output), Ok(Some(8)));
    assert_eq!(u64::from_ne_bytes(output), 3);
}

#[test]
fn realtime_absolute_state_reprojects_and_counts_wall_step_expirations() {
    let mut state = TimerfdState {
        expiry_ns: 100,
        interval_ns: 10,
        realtime_absolute: true, settime_flags: 0,
        ..TimerfdState::new(0)
    };
    assert_eq!(state.projected_expiry(20, 80), 40);
    assert_eq!(state.projected_expiry(20, 120), 20);
    let snapshot = state.snapshot(20, 125);
    assert_eq!(snapshot, uapi::Itimerspec { interval_ns: 10, value_ns: 5 });
    assert_eq!(state.expiry_ns, 130);
    assert_eq!(state.ticks, 3);
}

#[test]
fn crossed_realtime_expiration_survives_a_backward_clock_step() {
    let mut state = TimerfdState::new(0);
    let (_, canceled) = state.install(20, 80, 100, 0, false, true, 0);
    assert!(!canceled);
    assert_eq!(state.realtime_projection_ns, 40);

    assert!(!state.note_clock_was_set(1, 45, 45, 50));
    assert_eq!(state.expiry_ns, 0);
    assert_eq!(state.realtime_projection_ns, 0);
    assert_eq!(state.ticks, 1);

    let mut output = [0u8; 8];
    assert_eq!(timerfd_take_expirations(&mut state, 45, 50, &mut output), Ok(Some(8)));
    assert_eq!(u64::from_ne_bytes(output), 1);
}

#[test]
fn clock_step_serializes_before_or_after_settime_state_lock() {
    let mut hook_first = TimerfdState {
        cancel_enabled: true,
        ..TimerfdState::new(0)
    };
    assert!(hook_first.note_clock_was_set(1, 0, 0, 0));
    let (_, canceled) = hook_first.install(0, 0, 10, 0, true, true, 0);
    assert!(canceled);
    assert!(!hook_first.cancel_pending);

    let mut settime_first = TimerfdState::new(0);
    let (_, canceled) = settime_first.install(0, 0, 10, 0, true, true, 0);
    assert!(!canceled);
    assert!(settime_first.note_clock_was_set(1, 0, 0, 0));
    let mut output = [0u8; 8];
    assert_eq!(timerfd_take_expirations(&mut settime_first, 0, 0, &mut output),
        Err(VfsError::Ecanceled));
}

#[test]
fn nonblocking_unexpired_read_is_eagain() {
    let inode = make_timerfd_inode(CLOCK_MONOTONIC);
    let timerfd = inode.private::<TimerfdData>().unwrap();
    timerfd.state.lock().expiry_ns = u64::MAX;
    let mut output = [0u8; 8];
    assert_eq!(TimerfdFileOps.read_nonblock(&inode, 0, &mut output),
        Err(VfsError::Eagain));
}

#[test]
fn settime_replacement_reports_forwarded_old_periodic_value() {
    let mut state = TimerfdState {
        expiry_ns: 10,
        interval_ns: 10,
        ..TimerfdState::disarmed()
    };
    let replacement = TimerfdState {
        expiry_ns: 100,
        interval_ns: 25,
        cancel_enabled: true,
        ..TimerfdState::disarmed()
    };
    let old = state.replace(35, 0, replacement);
    assert_eq!(old, uapi::Itimerspec { interval_ns: 10, value_ns: 5 });
    assert_eq!(state, replacement);
}

#[test]
fn cancellation_supports_generation_zero_and_repeats_after_acknowledgement() {
    let mut state = TimerfdState {
        ticks: 4,
        cancel_enabled: true,
        ..TimerfdState::new(0)
    };
    assert!(state.note_clock_was_set(1, 0, 0, 0));
    let mut output = [0u8; 8];
    assert_eq!(timerfd_take_expirations(&mut state, 0, 0, &mut output),
        Err(VfsError::Ecanceled));
    assert_eq!(state.clock_generation_seen, 1);
    assert!(!state.cancel_pending);
    assert_eq!(state.ticks, 0);
    assert!(state.note_clock_was_set(2, 0, 0, 0));
    assert_eq!(timerfd_take_expirations(&mut state, 0, 0, &mut output),
        Err(VfsError::Ecanceled));
}

#[test]
fn clock_step_notifier_wakes_disarmed_cancel_timer_poll_source() {
    let inode = make_timerfd_inode(CLOCK_REALTIME);
    let timerfd = inode.private::<TimerfdData>().unwrap();
    let generation = sched::clock::realtime_change_generation();
    {
        let mut state = timerfd.state.lock();
        state.clock_generation_seen = generation.wrapping_sub(1);
        state.cancel_enabled = true;
    }
    let before = timerfd.poll_subscribers.generation();
    timerfd_clock_was_set(monotonic_ns());
    assert!(timerfd.poll_subscribers.generation() > before);
    assert_eq!(TimerfdFileOps.poll(&inode), vfs::POLL_IN);
}

#[test]
fn gettime_checks_fd_before_output_and_preserves_state_on_copy_fault() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new(CLOCK_MONOTONIC);
    let bad_fd = syscall::SyscallArgs {
        a0: (fixture.fd + 1) as u64, a1: 0, ..Default::default()
    };
    assert_eq!(sys_timerfd_gettime(&bad_fd), neg(Errno::Ebadf));

    *fixture.data().state.lock() = TimerfdState {
        expiry_ns: u64::MAX,
        interval_ns: 1_000_000,
        ticks: 7,
        ..TimerfdState::disarmed()
    };
    let bad_output = syscall::SyscallArgs {
        a0: fixture.fd as u64, a1: hal::USER_VA_END, ..Default::default()
    };
    assert_eq!(sys_timerfd_gettime(&bad_output), neg(Errno::Efault));
    let state = *fixture.data().state.lock();
    assert_eq!(state.ticks, 7);
    assert_eq!(state.expiry_ns, u64::MAX);
}

#[test]
fn wire_validation_retains_negative_einval_and_accepts_gnome_retry() {
    let raw = |value_sec| uapi::RawItimerspec {
        interval_sec: 0,
        interval_nsec: 0,
        value_sec,
        value_nsec: 0,
    };
    assert_eq!(uapi::prepare_itimerspec(0, raw(-1)), Err(Errno::Einval));
    assert_eq!(uapi::prepare_itimerspec(0, raw(4_294_967_295)).unwrap().value_ns,
        4_294_967_295_000_000_000);
    assert_eq!(uapi::prepare_itimerspec(0, raw(i64::MAX)).unwrap().value_ns,
        syscall::time::KTIME_MAX_NS);
    assert_eq!(uapi::prepare_itimerspec(0, uapi::RawItimerspec {
        value_nsec: 1_000_000_000,
        ..raw(0)
    }), Err(Errno::Einval));
}

// A desktop wall-clock watcher arms `TFD_TIMER_ABSTIME|TFD_TIMER_CANCEL_ON_SET`
// on a CLOCK_REALTIME timerfd. That pair is the COMPLETE `timerfd_settime` flag
// set, so it is admitted end to end and arms the cancel wiring; the only EINVAL
// left on the path is the itimerspec import. Pinned because a live-session trace
// showed one EINVAL for this exact call shape and the flag mask was suspected —
// the flags are accepted, the value was not.
#[test]
fn abstime_cancel_on_set_pair_is_admitted_and_the_residual_einval_is_the_value() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new(CLOCK_REALTIME);
    const BOTH: u64 = TFD_TIMER_ABSTIME | uapi::TFD_TIMER_CANCEL_ON_SET;
    let value = wire(0, 0, i64::MAX, 0);
    assert_eq!(sys_timerfd_settime(&settime_args(fixture.fd, BOTH, &value, 0)), 0);
    let armed = *fixture.data().state.lock();
    assert!(armed.cancel_enabled);
    assert!(armed.realtime_absolute);
    assert_eq!(armed.settime_flags as u64, BOTH);
    assert_eq!(armed.expiry_ns, syscall::time::KTIME_MAX_NS);

    // Same flags, rejected values: a pre-1970 `tv_sec` and an out-of-range
    // `tv_nsec` in either member.
    for bad in [wire(0, 0, -1, 0), wire(0, 0, 0, 1_000_000_000),
        wire(-1, 0, 1, 0), wire(0, -1, 1, 0)] {
        assert_eq!(sys_timerfd_settime(&settime_args(fixture.fd, BOTH, &bad, 0)),
            neg(Errno::Einval));
    }
    // One bit above the pair is the flag rejection, reported before the fd.
    assert_eq!(sys_timerfd_settime(&settime_args(fixture.fd, BOTH | 4, &value, 0)),
        neg(Errno::Einval));
}

// `TFD_TIMER_CANCEL_ON_SET` only arms cancellation together with
// `TFD_TIMER_ABSTIME` on a realtime clock; neither half alone does, and neither
// combination is an argument error.
#[test]
fn cancel_on_set_needs_abstime_and_a_realtime_clock_but_never_fails_the_call() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let value = wire(0, 0, 1, 0);
    let cancel_only = uapi::TFD_TIMER_CANCEL_ON_SET;
    let realtime = Fixture::new(CLOCK_REALTIME);
    assert_eq!(sys_timerfd_settime(&settime_args(realtime.fd, cancel_only, &value, 0)), 0);
    assert!(!realtime.data().state.lock().cancel_enabled);
    drop(realtime);

    let monotonic = Fixture::new(CLOCK_MONOTONIC);
    let both = TFD_TIMER_ABSTIME | cancel_only;
    assert_eq!(sys_timerfd_settime(&settime_args(monotonic.fd, both, &value, 0)), 0);
    assert!(!monotonic.data().state.lock().cancel_enabled);
}

#[test]
fn relative_deadline_clamps_to_linux_ktime_max() {
    assert_eq!(monotonic_deadline_from_value(
        0,
        syscall::time::KTIME_MAX_NS,
        1,
    ), syscall::time::KTIME_MAX_NS);
    assert_eq!(realtime_deadline(syscall::time::KTIME_MAX_NS, 1, 0),
        syscall::time::KTIME_MAX_NS);
}
