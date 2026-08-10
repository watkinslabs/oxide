// The per-destination metric slots and the netlink numbers that name them.
//
// The stored array is shorter than the ABI enumeration: the two microsecond
// metrics are not separate slots. `RTT` and `RTTVAR` are HELD in microseconds
// and reported twice — once raw under the microsecond attribute, once divided
// down under the millisecond one. A reader asking for either gets a consistent
// answer from one stored value.

/// Smoothed round-trip time in microseconds.
pub const RTT: usize = 0;
/// Round-trip variation in microseconds.
pub const RTTVAR: usize = 1;
/// Slow-start threshold this destination last settled at.
pub const SSTHRESH: usize = 2;
/// Congestion window this destination last settled at.
pub const CWND: usize = 3;
/// Reordering degree observed on the path.
pub const REORDERING: usize = 4;
/// Stored slots. The microsecond ABI metrics share the two above.
pub const COUNT: usize = REORDERING + 1;

/// `TCP_METRICS_A_METRICS_*`: the nested attribute number for a slot is its
/// index plus one. # C: O(1)
pub const fn attr(metric: usize) -> u16 { metric as u16 + 1 }

/// `TCP_METRICS_A_METRICS_RTT_US`.
pub const ATTR_RTT_US: u16 = 6;
/// `TCP_METRICS_A_METRICS_RTTVAR_US`.
pub const ATTR_RTTVAR_US: u16 = 7;

/// Microseconds in one millisecond.
pub const US_PER_MS: u32 = 1000;

/// The millisecond form of a microsecond-scaled metric. A held value never
/// reports as zero, which would read as "no metric" rather than "less than a
/// millisecond". # C: O(1)
pub const fn millis(value: u32) -> u32 {
    if value == 0 { return 0; }
    let ms = value / US_PER_MS;
    if ms == 0 { 1 } else { ms }
}

/// Whether an administrator pinned this slot against the connection-driven
/// update. `TCP_METRICS_ATTR_VALS` writes set the bit; the update path reads
/// it. # C: O(1)
pub const fn locked(lock: u32, metric: usize) -> bool {
    metric < u32::BITS as usize && lock & (1u32 << metric) != 0
}

/// The lock word with `metric` pinned. # C: O(1)
pub const fn with_lock(lock: u32, metric: usize) -> u32 {
    if metric < u32::BITS as usize { lock | (1u32 << metric) } else { lock }
}

#[cfg(test)]
#[path = "ids_tests.rs"]
mod tests;
