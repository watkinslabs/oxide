// `good_sigevent()` — how a `timer_create` sigevent becomes a notification.
// Kept free of user-memory and registry access so the accept/reject table is
// hosted-testable; `uapi` supplies the decoded struct and `syscalls` supplies
// the thread-id resolver.

use syscall::errno::Errno;

use crate::timer_model::Notify;

/// `include/uapi/asm-generic/siginfo.h`. SIGEV_THREAD_ID is a bit, not an
/// ordinal — the kernel BUILD_BUG_ONs that it shares no bit with the others.
pub const SIGEV_SIGNAL: i32 = 0;
pub const SIGEV_NONE: i32 = 1;
pub const SIGEV_THREAD: i32 = 2;
pub const SIGEV_THREAD_ID: i32 = 4;
/// `SIGALRM` — the signal a NULL sigevent defaults to.
pub const SIGALRM: u32 = 14;
/// `SIGRTMAX`; `good_sigevent()` rejects `sigev_signo` outside `1..=SIGRTMAX`.
pub const SIGNAL_MAX: i32 = 64;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Sigevent {
    pub value: u64,
    pub signo: i32,
    pub notify: i32,
    pub tid: i32,
}

/// Decide a timer's notification. A NULL sigevent is SIGEV_SIGNAL/SIGALRM
/// carrying the timer id as `si_value.sival_int`. SIGEV_THREAD is a userspace
/// notion the kernel validates and delivers exactly like SIGEV_SIGNAL — glibc
/// rewrites it to SIGEV_THREAD_ID before the syscall, but the raw ABI accepts
/// it and rejecting it would be a kernel-visible divergence.
/// `resolve_tid` implements `find_vpid` + `same_thread_group`.
/// # C: O(1) plus the resolver
pub fn notify_for(event: Option<Sigevent>, timer_id: usize,
    resolve_tid: impl FnOnce(i32) -> Option<u32>) -> Result<Notify, Errno>
{
    let Some(event) = event else {
        return Ok(Notify::Signal { signo: SIGALRM, value: timer_id as u64, target_tid: 0 });
    };
    match event.notify {
        SIGEV_NONE => Ok(Notify::None),
        SIGEV_SIGNAL | SIGEV_THREAD => {
            check_signo(event.signo)?;
            Ok(Notify::Signal { signo: event.signo as u32, value: event.value, target_tid: 0 })
        }
        SIGEV_THREAD_ID => {
            // `good_sigevent` resolves the thread BEFORE falling through to the
            // signo range check; both are EINVAL, but keep the order faithful.
            let target_tid = resolve_tid(event.tid).ok_or(Errno::Einval)?;
            check_signo(event.signo)?;
            Ok(Notify::Signal { signo: event.signo as u32, value: event.value, target_tid })
        }
        _ => Err(Errno::Einval),
    }
}

fn check_signo(signo: i32) -> Result<(), Errno> {
    if (1..=SIGNAL_MAX).contains(&signo) { Ok(()) } else { Err(Errno::Einval) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(notify: i32, signo: i32, tid: i32) -> Option<Sigevent> {
        Some(Sigevent { value: 0xfeed, signo, notify, tid })
    }

    fn no_thread(_: i32) -> Option<u32> { None }
    fn thread(tid: i32) -> Option<u32> { (tid == 77).then_some(77) }

    #[test]
    fn null_sigevent_defaults_to_sigalrm_carrying_the_timer_id() {
        assert_eq!(notify_for(None, 5, no_thread),
            Ok(Notify::Signal { signo: SIGALRM, value: 5, target_tid: 0 }));
        assert_eq!(notify_for(None, 0, no_thread),
            Ok(Notify::Signal { signo: SIGALRM, value: 0, target_tid: 0 }));
    }

    #[test]
    fn sigev_none_takes_no_signal_and_ignores_the_signo_field() {
        assert_eq!(notify_for(event(SIGEV_NONE, 0, 0), 1, no_thread), Ok(Notify::None));
        assert_eq!(notify_for(event(SIGEV_NONE, 999, 0), 1, no_thread), Ok(Notify::None),
            "good_sigevent falls straight through to `return pid` for SIGEV_NONE");
    }

    #[test]
    fn sigev_thread_is_accepted_and_behaves_exactly_like_sigev_signal() {
        let signal = notify_for(event(SIGEV_SIGNAL, 34, 0), 1, no_thread);
        let thread_notify = notify_for(event(SIGEV_THREAD, 34, 0), 1, no_thread);
        assert_eq!(signal, Ok(Notify::Signal { signo: 34, value: 0xfeed, target_tid: 0 }));
        assert_eq!(thread_notify, signal,
            "the kernel switch falls SIGEV_THREAD through to the SIGEV_SIGNAL arm");
    }

    #[test]
    fn signo_outside_one_to_sigrtmax_is_einval_for_every_signal_mode() {
        for notify in [SIGEV_SIGNAL, SIGEV_THREAD] {
            for signo in [0, -1, SIGNAL_MAX + 1, i32::MAX] {
                assert_eq!(notify_for(event(notify, signo, 0), 1, no_thread),
                    Err(Errno::Einval));
            }
            assert!(notify_for(event(notify, 1, 0), 1, no_thread).is_ok());
            assert!(notify_for(event(notify, SIGNAL_MAX, 0), 1, no_thread).is_ok());
        }
    }

    #[test]
    fn sigev_thread_id_requires_a_thread_of_the_callers_own_group() {
        assert_eq!(notify_for(event(SIGEV_THREAD_ID, 34, 77), 1, thread),
            Ok(Notify::Signal { signo: 34, value: 0xfeed, target_tid: 77 }));
        assert_eq!(notify_for(event(SIGEV_THREAD_ID, 34, 78), 1, thread), Err(Errno::Einval));
        assert_eq!(notify_for(event(SIGEV_THREAD_ID, 34, 0), 1, thread), Err(Errno::Einval));
        assert_eq!(notify_for(event(SIGEV_THREAD_ID, 999, 77), 1, thread), Err(Errno::Einval));
    }

    #[test]
    fn unknown_sigev_notify_values_are_einval() {
        for notify in [3, 5, 6, -1, i32::MIN] {
            assert_eq!(notify_for(event(notify, 34, 77), 1, thread), Err(Errno::Einval));
        }
    }
}
