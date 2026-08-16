// Per-frequency occupancy and the transition matrix.
//
// Occupancy is accumulated in nanoseconds and reported in the hundredths of a
// second the attribute has always used, because that is what every reader of
// it divides by.

use alloc::string::String;
use alloc::vec::Vec;

/// Ticks per second the occupancy attribute reports in.
pub const USER_HZ: u64 = 100;
/// Nanoseconds per second.
pub const NSEC_PER_SEC: u64 = 1_000_000_000;

/// Occupancy in the units the attribute reports. # C: O(1)
pub fn ns_to_clock_t(ns: u64) -> u64 { ns / (NSEC_PER_SEC / USER_HZ) }

/// Transition history of one policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Stats {
    /// Every frequency the policy can be at, ascending, kilohertz.
    pub freqs: Vec<u32>,
    /// Nanoseconds spent at each, indexed alongside `freqs`.
    pub time_ns: Vec<u64>,
    /// Transition counts, `from * len + to`.
    pub table: Vec<u64>,
    pub total_trans: u64,
    /// Index of the frequency the policy is at.
    pub current: usize,
    /// When the current frequency was entered.
    pub entered_ns: u64,
}

impl Stats {
    /// Fresh statistics over `freqs`, starting at `cur`. # C: O(N²)
    pub fn new(freqs: &[u32], cur: u32) -> Stats {
        let len = freqs.len();
        Stats {
            freqs: freqs.to_vec(),
            time_ns: alloc::vec![0; len],
            table: alloc::vec![0; len * len],
            total_trans: 0,
            current: freqs.iter().position(|freq| *freq == cur).unwrap_or(0),
            entered_ns: 0,
        }
    }

    /// Account a move to `freq`. A move to the frequency already in force
    /// accrues occupancy without counting as a transition: nothing was
    /// programmed. # C: O(N)
    pub fn record(&mut self, freq: u32, now_ns: u64) {
        let Some(to) = self.freqs.iter().position(|entry| *entry == freq) else { return; };
        let elapsed = now_ns.saturating_sub(self.entered_ns);
        if let Some(slot) = self.time_ns.get_mut(self.current) {
            *slot = slot.saturating_add(elapsed);
        }
        self.entered_ns = now_ns;
        if to == self.current { return; }
        let width = self.freqs.len();
        if let Some(slot) = self.table.get_mut(self.current * width + to) { *slot += 1; }
        self.total_trans += 1;
        self.current = to;
    }

    /// Occupancy with the current frequency's share brought up to `now_ns`.
    /// # C: O(N)
    pub fn time_ns_at(&self, now_ns: u64) -> Vec<u64> {
        let mut times = self.time_ns.clone();
        if let Some(slot) = times.get_mut(self.current) {
            *slot = slot.saturating_add(now_ns.saturating_sub(self.entered_ns));
        }
        times
    }

    /// Clear the counters without disturbing the policy. # C: O(N²)
    pub fn reset(&mut self, now_ns: u64) {
        self.time_ns.iter_mut().for_each(|slot| *slot = 0);
        self.table.iter_mut().for_each(|slot| *slot = 0);
        self.total_trans = 0;
        self.entered_ns = now_ns;
    }

    /// Body of `time_in_state`: one `<khz> <ticks>` line per frequency.
    /// # C: O(N)
    pub fn time_in_state_body(&self, now_ns: u64) -> Vec<u8> {
        let times = self.time_ns_at(now_ns);
        let mut body = String::new();
        for (index, freq) in self.freqs.iter().enumerate() {
            let ticks = ns_to_clock_t(times.get(index).copied().unwrap_or(0));
            let _ = core::fmt::Write::write_fmt(&mut body, format_args!("{freq} {ticks}\n"));
        }
        body.into_bytes()
    }

    /// Body of `trans_table`. # C: O(N²)
    pub fn trans_table_body(&self) -> Vec<u8> {
        const COLUMN: usize = 9;
        let width = self.freqs.len();
        let mut body = String::from("   From  :    To\n");
        let _ = core::fmt::Write::write_fmt(&mut body,
            format_args!("{:>width$} : ", "", width = COLUMN));
        for freq in &self.freqs {
            let _ = core::fmt::Write::write_fmt(&mut body,
                format_args!("{freq:>COLUMN$} "));
        }
        body.push('\n');
        for from in 0..width {
            let _ = core::fmt::Write::write_fmt(&mut body,
                format_args!("{:>COLUMN$}: ", self.freqs[from]));
            for to in 0..width {
                let count = self.table.get(from * width + to).copied().unwrap_or(0);
                let _ = core::fmt::Write::write_fmt(&mut body,
                    format_args!("{count:>COLUMN$} "));
            }
            body.push('\n');
        }
        body.into_bytes()
    }
}

#[cfg(test)]
#[path = "tests/stats.rs"]
mod tests;
