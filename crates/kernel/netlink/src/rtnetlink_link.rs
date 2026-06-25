use alloc::vec::Vec;

use crate::rtnetlink::{ifla, put_nlattr};

#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct LinkStats64 {
    pub(crate) rx_packets: u64,
    pub(crate) tx_packets: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_errors: u64,
    pub(crate) tx_errors: u64,
    pub(crate) rx_dropped: u64,
    pub(crate) tx_dropped: u64,
}

impl LinkStats64 {
    pub const SIZE: usize = 25 * 8;

    /// Serialize Linux `struct rtnl_link_stats64`. # C: O(1)
    fn write_to(&self, out: &mut [u8]) {
        let fields = [
            self.rx_packets,
            self.tx_packets,
            self.rx_bytes,
            self.tx_bytes,
            self.rx_errors,
            self.tx_errors,
            self.rx_dropped,
            self.tx_dropped,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        for (i, v) in fields.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&v.to_ne_bytes());
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
impl From<net::NetStats> for LinkStats64 {
    fn from(s: net::NetStats) -> Self {
        Self {
            rx_packets: s.rx_packets,
            tx_packets: s.tx_packets,
            rx_bytes: s.rx_bytes,
            tx_bytes: s.tx_bytes,
            rx_errors: s.rx_errors,
            tx_errors: s.tx_errors,
            rx_dropped: s.rx_dropped,
            tx_dropped: s.tx_dropped,
        }
    }
}

/// Append Linux `IFLA_STATS64`. # C: O(1)
pub(crate) fn put_link_stats64(out: &mut Vec<u8>, stats: LinkStats64) {
    let mut payload = [0u8; LinkStats64::SIZE];
    stats.write_to(&mut payload);
    put_nlattr(out, ifla::IFLA_STATS64, &payload);
}
