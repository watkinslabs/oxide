// The `/sys/power` surface as data and two functions, per `32a§11`.
//
// The sysfs crate registers names and forwards bytes; every decision — which
// labels are listed, what a write means, which errno a bad write is — is here,
// where it is ungated and tested. A `/sys/power` attribute whose behaviour
// lived in the sysfs crate would be target-gated and therefore uncheckable.

use alloc::vec::Vec;

use crate::decide::{Error, KResult};
use super::{attrs, ops, platform, run, state, stats, tunables, wakeup};
use super::state::SuspendState;

/// A `/sys/power` attribute: its name and whether userspace may write it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PowerAttr { pub name: &'static str, pub writable: bool }

/// The attributes directly under `/sys/power`.
pub const ATTRS: [PowerAttr; 6] = [
    PowerAttr { name: "state",             writable: true },
    PowerAttr { name: "mem_sleep",         writable: true },
    PowerAttr { name: "wakeup_count",      writable: true },
    PowerAttr { name: "pm_async",          writable: true },
    PowerAttr { name: "pm_debug_messages", writable: true },
    PowerAttr { name: "sync_on_suspend",   writable: true },
];

/// The read-only attributes under `/sys/power/suspend_stats`.
pub const STATS_ATTRS: [&str; 16] = attrs::STATS_ATTRS;

/// Read one `/sys/power` attribute.
/// # C: O(N_wakeups) for `wakeup_count`, O(1) otherwise
/// # Sleeps: `wakeup_count` waits for active wakeup sources
pub fn show(attr: &str) -> KResult<Vec<u8>> {
    let o = ops::suspend_ops();
    let body = match attr {
        "state"     => attrs::render_state(state::pm_states(o)),
        "mem_sleep" => attrs::render_mem_sleep(state::mem_sleep_states(o),
                           tunables::mem_sleep_current()),
        "wakeup_count" => return render_wakeup_count(
            wakeup::SYSTEM.get_wakeup_count_blocking()),
        "pm_async"          => attrs::render_bool(tunables::pm_async()),
        "pm_debug_messages" => attrs::render_bool(tunables::pm_debug_messages()),
        "sync_on_suspend"   => attrs::render_bool(tunables::sync_on_suspend()),
        _ => return Err(Error::Nodata),
    };
    Ok(attrs::bytes(body))
}

/// Render Linux `pm_get_wakeup_count`'s result for sysfs. # C: O(1)
fn render_wakeup_count(count: Option<u32>) -> KResult<Vec<u8>> {
    let Some(count) = count else { return Err(Error::Intr) };
    Ok(attrs::bytes(attrs::render_u64(u64::from(count))))
}

/// Read one `/sys/power/suspend_stats` attribute. # C: O(1)
pub fn show_stat(attr: &str) -> KResult<Vec<u8>> {
    match attrs::render_stat(&stats::STATS, attr) {
        Some(s) => Ok(attrs::bytes(s)),
        None => Err(Error::Nodata),
    }
}

/// Write one `/sys/power` attribute.
///
/// A write to `state` runs the whole transition and returns only once the
/// machine is awake again, which is the behaviour userspace depends on: the
/// `write` returning is how a suspend manager knows the resume finished.
/// # C: O(N_devices + N_tasks) for `state`, O(1) otherwise
/// # Sleeps: yes for `state`
pub fn store(attr: &str, buf: &[u8]) -> KResult<()> {
    match attr {
        "state"             => store_state(buf),
        "mem_sleep"         => store_mem_sleep(buf),
        "wakeup_count"      => store_wakeup_count(buf),
        "pm_async"          => set_bool(buf, tunables::set_pm_async),
        "pm_debug_messages" => set_bool(buf, tunables::set_pm_debug_messages),
        "sync_on_suspend"   => set_bool(buf, tunables::set_sync_on_suspend),
        _ => Err(Error::Inval),
    }
}

fn set_bool(buf: &[u8], set: fn(bool)) -> KResult<()> {
    match tunables::parse_bool(buf) { Some(v) => { set(v); Ok(()) } None => Err(Error::Inval) }
}

fn store_state(buf: &[u8]) -> KResult<()> {
    let o = ops::suspend_ops();
    let written = state::decode_state(state::pm_states(o), buf);
    if written == SuspendState::On { return Err(Error::Inval); }
    let target = state::resolve_target(written, tunables::mem_sleep_current());
    run::pm_suspend(target, &super::wire::backend(), platform::installed())
}

fn store_mem_sleep(buf: &[u8]) -> KResult<()> {
    if tunables::transition_in_progress() { return Err(Error::Busy); }
    let o = ops::suspend_ops();
    let s = state::decode_mem_sleep(state::mem_sleep_states(o), buf);
    if s == SuspendState::On { return Err(Error::Inval); }
    tunables::set_mem_sleep_current(s);
    Ok(())
}

fn store_wakeup_count(buf: &[u8]) -> KResult<()> {
    if tunables::transition_in_progress() { return Err(Error::Busy); }
    let Some(v) = tunables::parse_u32(buf) else { return Err(Error::Inval) };
    if wakeup::SYSTEM.save_wakeup_count(v) { Ok(()) } else { Err(Error::Inval) }
}

/// Pick the deepest available `mem_sleep` mechanism, once the platform tables
/// are installed. Boot calls this after arch init so `mem` means the deepest
/// state the firmware admits rather than always suspend-to-idle.
/// # C: O(1)
pub fn init_mem_sleep_default() {
    tunables::set_mem_sleep_current(state::default_mem_sleep(ops::suspend_ops()));
}

#[cfg(test)]
#[path = "sysfs_api/tests.rs"]
mod tests;
