// The `/sys/devices/system/cpu/cpu<N>/cpuidle/` surface. Owned here, not in
// the filesystem layer: the unit every duration attribute reports in is a
// cpuidle decision, and a microsecond figure rendered from a nanosecond
// counter is a thousand-fold error that reads as a plausible number.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use kstrtox::{kstrtoul, BASE_AUTO};
use vfs::{KResult, VfsError};

use crate::driver::{driver, Driver};
use crate::governor::{available_names, by_name};
use crate::limits::ns_to_us;
use crate::uapi::{FLAG_OFF, NULL_TEXT, STATUS_DISABLED, STATUS_ENABLED};

/// Read-only attribute mode.
pub const RO: u16 = 0o444;
/// Read-write attribute mode.
pub const RW: u16 = 0o644;

/// Per-state attribute names, in listing order.
pub const STATE_ATTRS: &[(&str, u16)] = &[
    ("name", RO), ("desc", RO), ("latency", RO), ("residency", RO), ("power", RO),
    ("usage", RO), ("time", RO), ("above", RO), ("below", RO), ("rejected", RO),
    ("default_status", RO), ("disable", RW),
];

/// Attribute names directly under the per-CPU `cpuidle` directory.
pub const DIR_ATTRS: &[(&str, u16)] = &[
    ("current_driver", RO), ("current_governor", RW), ("available_governors", RO),
    ("current_governor_ro", RO),
];

/// Directory name of state `index`. # C: O(1)
pub fn state_dir(index: usize) -> String {
    let mut name = String::from("state");
    let _ = core::fmt::Write::write_fmt(&mut name, format_args!("{index}"));
    name
}

/// Parse a `state<N>` directory name. # C: O(n)
pub fn parse_state_dir(name: &str) -> Option<usize> {
    name.strip_prefix("state").and_then(|digits| digits.parse().ok())
}

/// How many state directories a CPU publishes. # C: O(1)
pub fn state_count() -> usize { driver().map_or(0, |drv| drv.states().len()) }

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

/// Text for a name or description the driver left empty. # C: O(1)
fn text_or_null(text: &str) -> &str { if text.is_empty() { NULL_TEXT } else { text } }

/// Render one per-state attribute.
///
/// `latency`, `residency` and `time` report microseconds. The first two are
/// declared by the driver and the third accumulated by the core, all three in
/// nanoseconds internally, and all three are converted here. # C: O(1)
pub fn show_state(drv: &Arc<Driver>, cpu: usize, index: usize, attr: &str) -> KResult<Vec<u8>> {
    let state = drv.states().get(index).ok_or(VfsError::Enoent)?;
    let usage = drv.usage(cpu).ok_or(VfsError::Enoent)?;
    let counters = usage.get(index).copied().ok_or(VfsError::Enoent)?;
    match attr {
        "name" => Ok(line(text_or_null(&state.name))),
        "desc" => Ok(line(text_or_null(&state.desc))),
        "latency" => Ok(number(ns_to_us(state.exit_latency_ns))),
        "residency" => Ok(number(ns_to_us(state.target_residency_ns))),
        "power" => Ok(number(u64::from(state.power_uw))),
        "usage" => Ok(number(counters.usage)),
        "time" => Ok(number(ns_to_us(counters.time_ns))),
        "above" => Ok(number(counters.above)),
        "below" => Ok(number(counters.below)),
        "rejected" => Ok(number(counters.rejected)),
        "default_status" => Ok(line(if state.flags & FLAG_OFF != 0 { STATUS_DISABLED }
                                    else { STATUS_ENABLED })),
        "disable" => Ok(number(u64::from(counters.user_disabled()))),
        _ => Err(VfsError::Enoent),
    }
}

/// Consume a write to one per-state attribute. # C: O(1)
pub fn store_state(drv: &Arc<Driver>, cpu: usize, index: usize, attr: &str, buf: &[u8])
    -> KResult<usize>
{
    if attr != "disable" { return Err(VfsError::Eacces); }
    let value = kstrtoul(buf, BASE_AUTO).map_err(|_| VfsError::Einval)?;
    drv.set_disable(cpu, index, value != 0)?;
    Ok(buf.len())
}

/// Render one attribute of the per-CPU `cpuidle` directory. # C: O(1)
pub fn show_dir(drv: &Arc<Driver>, attr: &str) -> KResult<Vec<u8>> {
    match attr {
        "current_driver" => Ok(line(drv.name())),
        "current_governor" | "current_governor_ro" => Ok(line(drv.governor().name)),
        "available_governors" => Ok(available_names().into_bytes()),
        _ => Err(VfsError::Enoent),
    }
}

/// Consume a write to the per-CPU `cpuidle` directory. Only the writable
/// governor attribute takes one; the read-only alias exists so a reader can
/// see the selection without being able to change it. # C: O(N_cpus)
pub fn store_dir(drv: &Arc<Driver>, attr: &str, buf: &[u8]) -> KResult<usize> {
    if attr != "current_governor" { return Err(VfsError::Eacces); }
    let text = core::str::from_utf8(buf).map_err(|_| VfsError::Einval)?;
    let governor = by_name(text).ok_or(VfsError::Einval)?;
    drv.set_governor(governor);
    Ok(buf.len())
}

#[cfg(test)]
#[path = "tests/attrs.rs"]
mod tests;
