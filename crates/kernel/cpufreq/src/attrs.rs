// The `/sys/devices/system/cpu/cpu<N>/cpufreq/` surface.
//
// Every frequency attribute is kilohertz and the transition latency is
// nanoseconds. A governor daemon reads these and writes limits back in the
// same units, so a figure rendered in the wrong one does not fail — it caps
// the machine at a thousandth of the intended speed.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use kstrtox::{kstrtoul, BASE_AUTO};
use vfs::{KResult, VfsError};

use crate::driver::{cur_freq, driver, hardware_freq, set_boost, set_governor};
use crate::governor::available_names;
use crate::policy::{LimitSource, Policy};
#[cfg(test)]
use crate::policy::Request;
use crate::uapi::UNKNOWN_TEXT;

/// Read-only attribute mode.
pub const RO: u16 = 0o444;
/// Read-write attribute mode.
pub const RW: u16 = 0o644;
/// Write-only attribute mode.
pub const WO: u16 = 0o200;

/// Attributes directly under the per-CPU `cpufreq` directory.
pub const ATTRS: &[(&str, u16)] = &[
    ("cpuinfo_min_freq", RO), ("cpuinfo_max_freq", RO), ("cpuinfo_cur_freq", RO),
    ("cpuinfo_transition_latency", RO),
    ("scaling_min_freq", RW), ("scaling_max_freq", RW), ("scaling_cur_freq", RO),
    ("scaling_driver", RO), ("scaling_governor", RW), ("scaling_available_governors", RO),
    ("scaling_available_frequencies", RO), ("scaling_setspeed", RW),
    ("affected_cpus", RO), ("related_cpus", RO), ("boost", RW),
];

/// Attributes under the `stats` subdirectory.
pub const STATS_ATTRS: &[(&str, u16)] = &[
    ("total_trans", RO), ("time_in_state", RO), ("trans_table", RO), ("reset", WO),
];

/// Name of the statistics subdirectory.
pub const STATS_DIR: &str = "stats";

/// `scaling_driver` text before any driver has registered.
pub const NO_DRIVER_TEXT: &str = "none";

fn line(text: &str) -> Vec<u8> {
    let mut body = String::from(text);
    body.push('\n');
    body.into_bytes()
}

fn number(value: u64) -> Vec<u8> {
    let mut body = String::new();
    let _ = core::fmt::Write::write_fmt(&mut body, format_args!("{value}\n"));
    body.into_bytes()
}

/// Body of `scaling_available_frequencies`: ascending, each followed by a
/// space, then the newline. # C: O(N_entries)
pub fn available_frequencies(policy: &Arc<Policy>) -> Vec<u8> {
    let mut body = String::new();
    for freq in policy.table.available(policy.boost()) {
        let _ = core::fmt::Write::write_fmt(&mut body, format_args!("{freq} "));
    }
    body.push('\n');
    body.into_bytes()
}

/// Render one attribute of the `cpufreq` directory. # C: O(N_entries)
pub fn show(policy: &Arc<Policy>, attr: &str) -> KResult<Vec<u8>> {
    let limits = policy.limits();
    match attr {
        "cpuinfo_min_freq" => Ok(number(u64::from(policy.hw.min))),
        "cpuinfo_max_freq" => Ok(number(u64::from(policy.hw.max))),
        "cpuinfo_cur_freq" => match hardware_freq(policy) {
            Some(freq) => Ok(number(u64::from(freq))),
            None => Ok(line(UNKNOWN_TEXT)),
        },
        "cpuinfo_transition_latency" => Ok(number(policy.transition_latency_ns)),
        "scaling_min_freq" => Ok(number(u64::from(limits.min))),
        "scaling_max_freq" => Ok(number(u64::from(limits.max))),
        "scaling_cur_freq" => Ok(number(u64::from(cur_freq(policy).unwrap_or(policy.cur())))),
        "scaling_driver" => match driver() {
            Some(driver) => Ok(line(&driver.name)),
            None => Ok(line(NO_DRIVER_TEXT)),
        },
        "scaling_governor" => Ok(line(policy.governor())),
        "scaling_available_governors" => Ok(available_names().into_bytes()),
        "scaling_available_frequencies" => Ok(available_frequencies(policy)),
        "scaling_setspeed" => match policy.setspeed() {
            Some(freq) => Ok(number(u64::from(freq))),
            None => Ok(line(UNKNOWN_TEXT)),
        },
        "affected_cpus" => Ok(Policy::cpu_list(&policy.cpus).into_bytes()),
        "related_cpus" => Ok(Policy::cpu_list(&policy.related_cpus).into_bytes()),
        "boost" => Ok(number(u64::from(policy.boost()))),
        _ => Err(VfsError::Enoent),
    }
}

/// Consume a write to the `cpufreq` directory.
///
/// A limit write is recorded as the user's own request and re-aggregated, not
/// written straight into the effective limits: the platform's ceiling and a
/// thermal cap hold their own requests, and a write that overwrote the pair
/// would release both. # C: O(N_entries)
pub fn store(policy: &Arc<Policy>, attr: &str, buf: &[u8], now_ns: u64) -> KResult<usize> {
    match attr {
        "scaling_min_freq" | "scaling_max_freq" => {
            let value = parse_khz(buf)?;
            let mut request = policy.request(LimitSource::User);
            if attr == "scaling_min_freq" { request.min = Some(value); }
            else { request.max = Some(value); }
            crate::driver::set_limits(policy, LimitSource::User, request, now_ns)?;
            Ok(buf.len())
        }
        "scaling_governor" => {
            let text = core::str::from_utf8(buf).map_err(|_| VfsError::Einval)?;
            set_governor(policy, text)?;
            Ok(buf.len())
        }
        "scaling_setspeed" => {
            let value = parse_khz(buf)?;
            policy.with_state(|state| state.setspeed = Some(value));
            let target = crate::governor::simple::userspace(
                &crate::driver::snapshot(policy), &crate::governor::Demand::default());
            if let Some(target) = target { crate::driver::drive(policy, target, now_ns)?; }
            Ok(buf.len())
        }
        "boost" => {
            let value = parse_khz(buf)?;
            if !set_boost(policy, value != 0) { return Err(VfsError::Einval); }
            Ok(buf.len())
        }
        _ => Err(VfsError::Eacces),
    }
}

/// Parse a kilohertz figure written to an attribute. # C: O(n)
fn parse_khz(buf: &[u8]) -> KResult<u32> {
    let value = kstrtoul(buf, BASE_AUTO).map_err(|_| VfsError::Einval)?;
    u32::try_from(value).map_err(|_| VfsError::Erange)
}

/// Render one attribute of the `stats` subdirectory. # C: O(N_entries²)
pub fn show_stats(policy: &Arc<Policy>, attr: &str, now_ns: u64) -> KResult<Vec<u8>> {
    policy.with_state(|state| match attr {
        "total_trans" => Ok(number(state.stats.total_trans)),
        "time_in_state" => Ok(state.stats.time_in_state_body(now_ns)),
        "trans_table" => Ok(state.stats.trans_table_body()),
        "reset" => Err(VfsError::Eacces),
        _ => Err(VfsError::Enoent),
    })
}

/// Consume a write to the `stats` subdirectory. # C: O(N_entries²)
pub fn store_stats(policy: &Arc<Policy>, attr: &str, buf: &[u8], now_ns: u64)
    -> KResult<usize>
{
    if attr != "reset" { return Err(VfsError::Eacces); }
    policy.with_state(|state| state.stats.reset(now_ns));
    Ok(buf.len())
}

#[cfg(test)]
#[path = "tests/attrs.rs"]
mod tests;
