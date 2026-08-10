// What a closing connection writes back about its destination.
//
// The rule throughout is that overestimating a path costs a little throughput
// and underestimating it costs retransmits, so a new sample larger than the
// stored one replaces it outright while a smaller one only decays the stored
// value. The congestion metrics are written differently depending on where
// the connection got to: in slow start the window it reached is a floor and
// nothing else is known; past slow start with no loss in flight the window is
// a real measurement and is averaged in; and a connection that left slow start
// through loss has a window that says nothing, so only the threshold and the
// reordering it observed are worth keeping.
//
// A connection that never got a round-trip sample, or that was still backing
// off when it closed, learned nothing about the path: it CLEARS the stored
// round-trip time rather than leaving a stale one for the next connection to
// be seeded from.

use super::ids;

/// The stored row, as the update reads and rewrites it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Row {
    pub vals: [u32; ids::COUNT],
    pub lock: u32,
}

impl Row {
    /// # C: O(1)
    pub const fn get(&self, metric: usize) -> u32 { self.vals[metric] }
    /// # C: O(1)
    const fn locked(&self, metric: usize) -> bool { ids::locked(self.lock, metric) }
    /// Write one slot unless an administrator pinned it. # C: O(1)
    fn set(&mut self, metric: usize, value: u32) {
        if !self.locked(metric) { self.vals[metric] = value; }
    }
}

/// Where a connection's congestion control had got to when it closed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Slow start has not been left. The window reached is a floor.
    InitialSlowStart,
    /// Past slow start with nothing lost in flight: the window is real.
    Open,
    /// Slow start was left through loss, so the window means nothing.
    Lossy,
}

/// The closing connection, in the terms the write-back is decided from.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Closing {
    /// Smoothed round-trip time in microseconds; zero means none was taken.
    pub srtt: u32,
    /// Mean deviation in microseconds, the estimator's own variation input.
    pub mdev: u32,
    pub cwnd: u32,
    pub ssthresh: u32,
    pub reordering: u32,
    pub phase: Phase,
    /// The retransmit timer was backing off, so nothing this connection
    /// measured describes the path.
    pub backing_off: bool,
    /// `net.ipv4.tcp_no_ssthresh_metrics_save`.
    pub no_ssthresh_save: bool,
    /// The namespace's `net.ipv4.tcp_reordering`. A connection still carrying
    /// the default observed nothing worth storing.
    pub default_reordering: u32,
}

/// What this connection leaves behind for the next one to the same
/// destination.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Update {
    /// Store this row, refreshing the entry's timestamp.
    Store(Row),
    /// Clear the round-trip time and change nothing else: the connection
    /// measured nothing, so a stored value would be believed on no evidence.
    /// A pinned round-trip time survives even this.
    ForgetRtt,
}

/// Fold one closing connection into the destination's row. # C: O(1)
pub fn update(row: Row, conn: Closing) -> Update {
    if conn.backing_off || conn.srtt == 0 { return Update::ForgetRtt; }
    let mut row = row;

    // Round trip: a larger sample replaces, a smaller one decays the stored
    // value by an eighth of the difference.
    let stored = row.get(ids::RTT);
    let drift = i64::from(stored) - i64::from(conn.srtt);
    let rtt = if drift <= 0 { conn.srtt } else { stored - (drift >> 3) as u32 };
    row.set(ids::RTT, rtt);

    // Variation: the same difference, halved, floored at the connection's own
    // deviation. A larger one replaces; a smaller one decays by a quarter.
    let mut deviation = (drift.unsigned_abs() as u32) >> 1;
    if deviation < conn.mdev { deviation = conn.mdev; }
    let stored = row.get(ids::RTTVAR);
    let rttvar = if deviation >= stored { deviation } else { stored - ((stored - deviation) >> 2) };
    row.set(ids::RTTVAR, rttvar);

    let save_ssthresh = !conn.no_ssthresh_save;
    match conn.phase {
        Phase::InitialSlowStart => {
            // Nothing has been lost yet, so the only claim available is that
            // the path took at least the window reached.
            let half = conn.cwnd >> 1;
            if save_ssthresh && row.get(ids::SSTHRESH) != 0 && half > row.get(ids::SSTHRESH) {
                row.set(ids::SSTHRESH, half);
            }
            if conn.cwnd > row.get(ids::CWND) { row.set(ids::CWND, conn.cwnd); }
        }
        Phase::Open => {
            if save_ssthresh {
                row.set(ids::SSTHRESH, core::cmp::max(conn.cwnd >> 1, conn.ssthresh));
            }
            row.set(ids::CWND, (row.get(ids::CWND) + conn.cwnd) >> 1);
        }
        Phase::Lossy => {
            row.set(ids::CWND, (row.get(ids::CWND) + conn.ssthresh) >> 1);
            if save_ssthresh && row.get(ids::SSTHRESH) != 0
                && conn.ssthresh > row.get(ids::SSTHRESH) {
                row.set(ids::SSTHRESH, conn.ssthresh);
            }
            // Reordering is only worth storing when the connection actually
            // observed some: one still carrying the namespace default saw
            // nothing the next connection needs to know.
            if row.get(ids::REORDERING) < conn.reordering
                && conn.reordering != conn.default_reordering {
                row.set(ids::REORDERING, conn.reordering);
            }
        }
    }
    Update::Store(row)
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
