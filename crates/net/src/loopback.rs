// `lo` netdev. xmit-time it just hands the packet straight back
// to the kernel's RX path (no L2 framing — loopback is a synthetic
// device that delivers pure L3 packets to itself).
//
// v1 hosted shape: an Arc<LoopbackDev> can be registered like any
// other NetDev; tx packets land in a Spinlock<Vec<Pkt>> ring that
// the test or the kernel rx-poll path can drain.

extern crate alloc;
use alloc::collections::VecDeque;

use sync::{Spinlock, Socket as RxLockClass};

use crate::addr::MacAddr;
use crate::netdev::{NetDev, NetError, NetResult, NetStats};
use core::sync::atomic::{AtomicU64, Ordering};
use crate::pkt::Pkt;

pub struct LoopbackDev {
    rx: Spinlock<VecDeque<Pkt>, RxLockClass>,
    rx_pkts:    AtomicU64,
    rx_bytes:   AtomicU64,
    tx_pkts:    AtomicU64,
    tx_bytes:   AtomicU64,
    tx_dropped: AtomicU64,
}

impl LoopbackDev {
    pub fn new() -> Self {
        Self {
            rx: Spinlock::new(VecDeque::new()),
            rx_pkts: AtomicU64::new(0), rx_bytes: AtomicU64::new(0),
            tx_pkts: AtomicU64::new(0), tx_bytes: AtomicU64::new(0),
            tx_dropped: AtomicU64::new(0),
        }
    }

    /// Drain one packet from the rx queue. Bumps rx counters.
    /// # C: O(1)
    pub fn rx_pop(&self) -> Option<Pkt> {
        let p = self.rx.lock().pop_front()?;
        self.rx_pkts.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(p.len() as u64, Ordering::Relaxed);
        Some(p)
    }

    /// Number of packets currently parked in rx.
    /// # C: O(1)
    pub fn rx_len(&self) -> usize { self.rx.lock().len() }
}

impl Default for LoopbackDev { fn default() -> Self { Self::new() } }

impl NetDev for LoopbackDev {
    fn name(&self) -> &str { "lo" }
    fn mac(&self)  -> MacAddr { MacAddr::ZERO }
    fn mtu(&self)  -> u32 { 65535 }
    fn xmit(&self, pkt: Pkt) -> NetResult<()> {
        // Loopback: tx → rx with no L2 frame. Caller already
        // populated `pkt.proto` (ETH_P_*) so the IP demux can
        // fire when soft-IRQ drains rx.
        let mut g = self.rx.lock();
        if g.len() >= 1024 {
            self.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(NetError::Enobufs);
        }
        let n = pkt.len() as u64;
        g.push_back(pkt);
        self.tx_pkts.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
        Ok(())
    }

    fn stats(&self) -> NetStats {
        NetStats {
            rx_packets: self.rx_pkts.load(Ordering::Relaxed),
            rx_bytes:   self.rx_bytes.load(Ordering::Relaxed),
            tx_packets: self.tx_pkts.load(Ordering::Relaxed),
            tx_bytes:   self.tx_bytes.load(Ordering::Relaxed),
            tx_dropped: self.tx_dropped.load(Ordering::Relaxed),
            ..NetStats::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkt::Pkt;

    #[test]
    fn xmit_routes_to_rx() {
        let lo = LoopbackDev::new();
        let mut p = Pkt::with_capacity(64, 256);
        p.put(5).unwrap().copy_from_slice(b"hello");
        lo.xmit(p).unwrap();
        assert_eq!(lo.rx_len(), 1);
        let got = lo.rx_pop().unwrap();
        assert_eq!(got.data(), b"hello");
    }

    #[test]
    fn rx_pop_returns_none_when_empty() {
        let lo = LoopbackDev::new();
        assert!(lo.rx_pop().is_none());
    }

    #[test]
    fn xmit_returns_enobufs_when_queue_full() {
        let lo = LoopbackDev::new();
        for _ in 0..1024 {
            let mut p = Pkt::with_capacity(8, 16);
            p.put(1).unwrap()[0] = b'x';
            lo.xmit(p).unwrap();
        }
        let mut p = Pkt::with_capacity(8, 16);
        p.put(1).unwrap()[0] = b'x';
        assert_eq!(lo.xmit(p).err().unwrap(), NetError::Enobufs);
    }

    #[test]
    fn pinned_constants() {
        let lo = LoopbackDev::new();
        assert_eq!(lo.name(), "lo");
        assert_eq!(lo.mac(), MacAddr::ZERO);
        assert_eq!(lo.mtu(), 65535);
    }
}
