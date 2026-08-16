// `/sys/power` attribute rendering and write parsing per `32a§11`.
//
// The rendering lives here rather than in the sysfs crate so it is testable
// without a filesystem: the bracket placement in `mem_sleep` and the
// space-to-newline conversion at the end of a list are the parts userspace
// parses, and both are easy to get subtly wrong.

use alloc::string::String;
use alloc::vec::Vec;

use super::state::{StateSet, SuspendState, ENTERABLE};
use super::stats::{StatStep, SuspendStats, NR_STEPS};

/// Render a label list: each member separated by a space, the trailing space
/// replaced by a newline. An empty set renders as nothing at all, which is what
/// a zero-length read reports.
/// # C: O(n)
pub fn render_labels(set: StateSet, label: fn(SuspendState) -> Option<&'static str>) -> String {
    let mut out = String::new();
    for s in ENTERABLE {
        if !set.contains(s) { continue; }
        if let Some(l) = label(s) { out.push_str(l); out.push(' '); }
    }
    terminate(out)
}

/// Render `mem_sleep`: the same list with `current` in brackets.
/// # C: O(n)
pub fn render_mem_sleep(set: StateSet, current: SuspendState) -> String {
    let mut out = String::new();
    for s in ENTERABLE {
        if !set.contains(s) { continue; }
        let Some(l) = s.mem_sleep_label() else { continue };
        if s == current { out.push('['); out.push_str(l); out.push(']'); }
        else { out.push_str(l); }
        out.push(' ');
    }
    terminate(out)
}

fn terminate(mut out: String) -> String {
    if out.pop().is_some() { out.push('\n'); }
    out
}

/// Render `/sys/power/state`. # C: O(n)
pub fn render_state(set: StateSet) -> String { render_labels(set, SuspendState::label) }

/// Render a decimal unsigned attribute. # C: O(log n)
pub fn render_u64(v: u64) -> String {
    let mut out = String::new();
    render_udec(&mut out, v);
    out.push('\n');
    out
}

/// Render a decimal signed attribute. # C: O(log n)
pub fn render_i32(v: i32) -> String {
    let mut out = String::new();
    if v < 0 { out.push('-'); }
    render_udec(&mut out, v.unsigned_abs() as u64);
    out.push('\n');
    out
}

/// Render a boolean attribute as the reference does: `0` or `1`. # C: O(1)
pub fn render_bool(v: bool) -> String { if v { String::from("1\n") } else { String::from("0\n") } }

/// Render a bare string attribute with its newline. # C: O(n)
pub fn render_str(s: &str) -> String {
    let mut out = String::from(s);
    out.push('\n');
    out
}

fn render_udec(out: &mut String, v: u64) {
    if v == 0 { out.push('0'); return; }
    let mut digits = [0u8; 20];
    let mut n = 0;
    let mut v = v;
    while v > 0 { digits[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
    while n > 0 { n -= 1; out.push(digits[n] as char); }
}

/// Every attribute name in `suspend_stats/`, in the reference's order.
pub const STATS_ATTRS: [&str; 16] = [
    "success", "fail",
    "failed_freeze", "failed_prepare", "failed_suspend", "failed_suspend_late",
    "failed_suspend_noirq", "failed_resume_noirq", "failed_resume_early", "failed_resume",
    "last_failed_dev", "last_failed_errno", "last_failed_step",
    "last_hw_sleep", "total_hw_sleep", "max_hw_sleep",
];

/// Render one `suspend_stats/` attribute, or `None` for an unknown name.
/// # C: O(1)
pub fn render_stat(stats: &SuspendStats, attr: &str) -> Option<String> {
    Some(match attr {
        "success" => render_u64(u64::from(stats.success())),
        "fail"    => render_u64(u64::from(stats.fail())),
        "last_failed_dev"   => render_str(stats.last_failed_dev().as_str()),
        "last_failed_errno" => render_i32(stats.last_failed_errno()),
        "last_failed_step"  => render_str(stats.last_failed_step().name()),
        "last_hw_sleep"     => render_u64(stats.last_hw_sleep()),
        "total_hw_sleep"    => render_u64(stats.total_hw_sleep()),
        "max_hw_sleep"      => render_u64(stats.max_hw_sleep()),
        other => {
            let step = other.strip_prefix("failed_").and_then(step_by_name)?;
            render_u64(u64::from(stats.step_failures(step)))
        }
    })
}

/// The step a `failed_<name>` attribute counts. # C: O(1)
pub fn step_by_name(name: &str) -> Option<StatStep> {
    (0..NR_STEPS).filter_map(StatStep::from_index).find(|s| s.name() == name)
}

/// Byte form of a rendered attribute, which is what the sysfs read returns.
/// # C: O(n)
pub fn bytes(s: String) -> Vec<u8> { s.into_bytes() }

#[cfg(test)]
#[path = "attrs/tests.rs"]
mod tests;
