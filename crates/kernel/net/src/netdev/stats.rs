// Sysfs projection of canonical network-interface counters.

use super::NetStats;

/// Linux `/sys/class/net/<if>/statistics/` field names in registration order.
pub const STAT_FIELDS: &[&str] = &[
    "rx_packets", "tx_packets", "rx_bytes", "tx_bytes",
    "rx_errors", "tx_errors", "rx_dropped", "tx_dropped",
    "multicast", "collisions",
    "rx_length_errors", "rx_over_errors", "rx_crc_errors",
    "rx_frame_errors", "rx_fifo_errors", "rx_missed_errors",
    "tx_aborted_errors", "tx_carrier_errors", "tx_fifo_errors",
    "tx_heartbeat_errors", "tx_window_errors",
    "rx_compressed", "tx_compressed", "rx_nohandler",
];

impl NetStats {
    /// Value of one statistics field, or `None` for an unknown name. # C: O(1)
    pub fn field(&self, name: &str) -> Option<u64> {
        Some(match name {
            "rx_packets" => self.rx_packets,
            "tx_packets" => self.tx_packets,
            "rx_bytes"   => self.rx_bytes,
            "tx_bytes"   => self.tx_bytes,
            "rx_errors"  => self.rx_errors,
            "tx_errors"  => self.tx_errors,
            "rx_dropped" => self.rx_dropped,
            "tx_dropped" => self.tx_dropped,
            n if STAT_FIELDS.contains(&n) => 0,
            _ => return None,
        })
    }
}
