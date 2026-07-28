// `perf_ioctl` — Linux `kernel/events/core.c` `_perf_ioctl()`.
//
// The command classification is a pure function so the `-ENOTTY` / `-EINVAL` /
// `-EBADF` split is hosted-testable; the arms that touch user memory or the fd
// table stay in `dispatch`.

use syscall::errno::Errno;

use super::event::{now_ns, PerfEvent};
use super::uapi::ioc;

/// What `_perf_ioctl` does with a command, independent of live state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerfIoctl {
    Enable,
    Disable,
    Reset,
    /// `_perf_event_refresh(event, arg)`.
    Refresh,
    /// `copy_from_user(u64)` then `_perf_event_period`.
    Period,
    /// `copy_to_user(primary_event_id)`.
    Id,
    /// `perf_event_set_output(event, fd)`.
    SetOutput,
    /// `perf_event_set_filter` — PMU-specific.
    SetFilter,
    /// `bpf_prog_get(arg)` then `__perf_event_set_bpf_prog`.
    SetBpf,
    /// `rb_toggle_paused` on the ring buffer.
    PauseOutput,
    /// `perf_event_query_prog_array`.
    QueryBpf,
    /// `perf_copy_attr` then `perf_event_modify_attr`.
    ModifyAttributes,
}

/// `_perf_ioctl`'s switch; `None` is its `default: return -ENOTTY`. # C: O(1)
pub fn classify(req: u64) -> Option<PerfIoctl> {
    Some(match req {
        ioc::ENABLE            => PerfIoctl::Enable,
        ioc::DISABLE           => PerfIoctl::Disable,
        ioc::RESET             => PerfIoctl::Reset,
        ioc::REFRESH           => PerfIoctl::Refresh,
        ioc::PERIOD            => PerfIoctl::Period,
        ioc::ID                => PerfIoctl::Id,
        ioc::SET_OUTPUT        => PerfIoctl::SetOutput,
        ioc::SET_FILTER        => PerfIoctl::SetFilter,
        ioc::SET_BPF           => PerfIoctl::SetBpf,
        ioc::PAUSE_OUTPUT      => PerfIoctl::PauseOutput,
        ioc::QUERY_BPF         => PerfIoctl::QueryBpf,
        ioc::MODIFY_ATTRIBUTES => PerfIoctl::ModifyAttributes,
        _ => return None,
    })
}

/// `_perf_event_refresh()`: "not supported on inherited events", and only a
/// sampling event has an overflow budget to refresh. # C: O(1)
pub fn refresh_result(inherit: bool, is_sampling: bool) -> Result<(), Errno> {
    if inherit || !is_sampling { return Err(Errno::Einval); }
    Ok(())
}

/// `_perf_event_period()`. `perf_event_check_period` is the PMU hook; the
/// software PMUs do not define one, so only the sign-bit rule applies.
/// # C: O(1)
pub fn period_result(is_sampling: bool, freq: bool, value: u64, sample_rate: i32)
    -> Result<(), Errno>
{
    if !is_sampling { return Err(Errno::Einval); }
    if value == 0   { return Err(Errno::Einval); }
    if freq {
        if value > sample_rate.max(0) as u64 { return Err(Errno::Einval); }
    } else if value & (1 << 63) != 0 {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// Apply the enable/disable/reset arms. `PERF_IOC_FLAG_GROUP` makes Linux walk
/// the whole group, so the caller passes every member. # C: O(members)
pub fn apply_state(members: &[alloc::sync::Arc<PerfEvent>], what: PerfIoctl) {
    let now = now_ns();
    for ev in members {
        let src = ev.sample();
        let mut g = ev.state.lock();
        match what {
            PerfIoctl::Enable  => g.counter.enable(src, now),
            PerfIoctl::Disable => g.counter.disable(src, now),
            PerfIoctl::Reset   => g.counter.reset(src),
            _ => {}
        }
    }
}
