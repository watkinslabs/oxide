// The cooling-device half of the class surface.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use kstrtox::{kstrtoul, BASE_AUTO};
use vfs::{KResult, VfsError};

use crate::cdev::CoolingDevice;
use crate::limits::NSEC_PER_MSEC;

use super::names;
use super::zone::{RO, RW};

/// Write-only attribute mode.
pub const WO: u16 = 0o200;

/// Attributes and modes a cooling device publishes. # C: O(1)
pub fn attrs() -> Vec<(String, u16)> {
    alloc::vec![
        (String::from(names::TYPE), RO),
        (String::from(names::MAX_STATE), RO),
        (String::from(names::CUR_STATE), RW),
        (String::from(names::TOTAL_TRANS), RO),
        (String::from(names::TIME_IN_STATE_MS), RO),
        (String::from(names::TRANS_TABLE), RO),
        (String::from(names::STATS_RESET), WO),
    ]
}

/// Occupancy rendered in the milliseconds the attribute name promises. The
/// accounting is in nanoseconds because that is what the monotonic clock
/// gives; reporting it unconverted would overstate every figure a
/// million-fold. # C: O(1)
pub fn ns_to_ms(ns: u64) -> u64 { ns / NSEC_PER_MSEC }

/// Body of `time_in_state_ms`: one `state<N> <ms>` line per state.
/// # C: O(N_states)
pub fn time_in_state_body(times_ns: &[u64]) -> Vec<u8> {
    let mut body = String::new();
    for (state, ns) in times_ns.iter().enumerate() {
        let _ = core::fmt::Write::write_fmt(
            &mut body, format_args!("state{state}\t{}\n", ns_to_ms(*ns)));
    }
    body.into_bytes()
}

/// Column width of every transition-table cell.
const TABLE_COLUMN: usize = 9;

/// Body of `trans_table`: a header naming the destination states, then one row
/// per source state. # C: O(N_states²)
pub fn trans_table_body(table: &[u64], states: usize) -> Vec<u8> {
    let mut body = String::from(" From  :    To\n");
    let _ = core::fmt::Write::write_fmt(&mut body, format_args!("{:>width$} :", "",
        width = TABLE_COLUMN));
    for state in 0..states {
        let _ = core::fmt::Write::write_fmt(&mut body, format_args!(" {:>width$}",
            alloc::format!("state{state}"), width = TABLE_COLUMN));
    }
    body.push('\n');
    for from in 0..states {
        let _ = core::fmt::Write::write_fmt(&mut body, format_args!("{:>width$} :",
            alloc::format!("state{from}"), width = TABLE_COLUMN));
        for to in 0..states {
            let count = table.get(from * states + to).copied().unwrap_or(0);
            let _ = core::fmt::Write::write_fmt(&mut body,
                format_args!(" {count:>width$}", width = TABLE_COLUMN));
        }
        body.push('\n');
    }
    body.into_bytes()
}

/// Render one cooling-device attribute. # C: O(N_states²)
pub fn show(cdev: &Arc<CoolingDevice>, attr: &str, now_ns: u64) -> KResult<Vec<u8>> {
    let mut body = String::new();
    match attr {
        names::TYPE => { body.push_str(cdev.ty()); body.push('\n'); }
        names::MAX_STATE => {
            let _ = core::fmt::Write::write_fmt(&mut body,
                format_args!("{}\n", cdev.max_state()));
        }
        names::CUR_STATE => {
            let state = cdev.cur_state()?;
            let _ = core::fmt::Write::write_fmt(&mut body, format_args!("{state}\n"));
        }
        names::TOTAL_TRANS => {
            let _ = core::fmt::Write::write_fmt(&mut body,
                format_args!("{}\n", cdev.transitions()));
        }
        names::TIME_IN_STATE_MS => return Ok(time_in_state_body(&cdev.time_in_state_ns(now_ns))),
        names::TRANS_TABLE => {
            let states = (cdev.max_state() as usize).saturating_add(1);
            return Ok(trans_table_body(&cdev.trans_table(), states));
        }
        names::STATS_RESET => return Err(VfsError::Eacces),
        _ => return Err(VfsError::Enoent),
    }
    Ok(body.into_bytes())
}

/// Consume a write to one cooling-device attribute.
///
/// A write to `cur_state` is a request, not a command: the zones bound to the
/// device may already be asking for something deeper, and the deepest request
/// still wins. Refusing to let a userspace write undercut an active thermal
/// trip is the whole point of the aggregation. # C: O(N_zones)
pub fn store(cdev: &Arc<CoolingDevice>, attr: &str, buf: &[u8], now_ns: u64) -> KResult<usize> {
    match attr {
        names::CUR_STATE => {
            let state = kstrtoul(buf, BASE_AUTO).map_err(|_| VfsError::Einval)?;
            if state > cdev.max_state() { return Err(VfsError::Einval); }
            let zones = crate::registry::zones();
            let demanded = zones.iter()
                .flat_map(|zone| zone.requests_for(cdev))
                .chain(core::iter::once(state));
            let effective = crate::governor::input::aggregate(demanded);
            cdev.set_cur_state(effective, now_ns)?;
            crate::registry::notify(&cdev.name());
            Ok(buf.len())
        }
        names::STATS_RESET => { cdev.reset_stats(now_ns); Ok(buf.len()) }
        _ => Err(VfsError::Eacces),
    }
}

/// `uevent` body for a cooling device. # C: O(1)
pub fn uevent_env(cdev: &Arc<CoolingDevice>) -> Vec<String> {
    alloc::vec![
        alloc::format!("DEVTYPE=thermal_cooling_device"),
        alloc::format!("NAME={}", cdev.ty()),
    ]
}

#[cfg(test)]
#[path = "../tests/attrs_cdev.rs"]
mod tests;
