use super::*;
use alloc::sync::Weak;

use crate::backlog::limits::{DEV_RX_WEIGHT, NETDEV_BUDGET, NETDEV_MAX_BACKLOG};
use crate::backlog::queue::{BacklogItem, BacklogPacket, RxVerdict, SoftnetRow};
pub(crate) use crate::backlog::queue::SoftnetData;

/// One receive source on this stack's poll list. `Weak` so a namespace that
/// retires its loopback needs no unregister call — the entry evaporates with
/// the device and the next poll prunes it.
pub(crate) struct RxPollEntry {
    pub(crate) iface: NetIfaceId,
    pub(crate) dev: Weak<LoopbackDev>,
}

impl NetStack {
    /// This CPU's backlog slot. # C: O(1)
    fn softnet_this_cpu(&self) -> &Spinlock<SoftnetData, StackLockClass> {
        &self.softnet[softirq::this_cpu()]
    }

    /// Put a receive source on this stack's poll list. Called once per device
    /// registration, under RTNL, so the bottom half never has to walk the
    /// namespace registry to find out what might have frames waiting.
    /// # C: O(N poll entries)
    pub(crate) fn register_rx_poll(&self, iface: NetIfaceId, dev: &Arc<LoopbackDev>) {
        let mut list = self.rx_poll.lock();
        list.retain(|e| e.dev.strong_count() > 0);
        list.push(RxPollEntry { iface, dev: Arc::downgrade(dev) });
    }

    /// Hand one frame to this CPU's backlog. The device's transmit-side caller
    /// is done with it at this point; everything after is bottom-half work.
    /// # C: O(1)
    pub fn netif_rx(&self, iface: NetIfaceId, pkt: Pkt) -> RxVerdict {
        self.softnet_this_cpu().lock().enqueue(BacklogItem {
            iface, generation: None, packet: BacklogPacket::L3(pkt),
        })
    }

    /// Queue one complete Ethernet frame from a loadable module. Its ingress
    /// generation is part of the item: an interface recycled before NET_RX
    /// drains it must not receive the former device's packet. # C: O(1)
    pub fn netif_rx_ethernet(&self, iface: NetIfaceId, generation: u64, pkt: Pkt,
        metadata: crate::PacketRxMetadata) -> RxVerdict
    {
        self.softnet_this_cpu().lock().enqueue(BacklogItem {
            iface, generation: Some(generation), packet: BacklogPacket::Ethernet { pkt, metadata },
        })
    }

    /// Move every frame waiting on a poll-list device into the backlog.
    /// Returns frames admitted; frames refused by a full backlog are dropped
    /// and accounted against both the device and the CPU, never re-queued.
    /// # C: O(N queued frames)
    fn poll_rx_sources(&self) -> usize {
        let sources: Vec<(NetIfaceId, Arc<LoopbackDev>)> = {
            let mut list = self.rx_poll.lock();
            list.retain(|e| e.dev.strong_count() > 0);
            list.iter().filter_map(|e| e.dev.upgrade().map(|d| (e.iface, d))).collect()
        };
        let mut moved = 0;
        for (iface, dev) in sources {
            let mut pulled = 0;
            while pulled <= NETDEV_MAX_BACKLOG {
                let Some(pkt) = dev.rx_pop() else { break };
                pulled += 1;
                match self.netif_rx(iface, pkt) {
                    RxVerdict::Success => moved += 1,
                    RxVerdict::Drop => dev.record_rx_dropped(),
                }
            }
        }
        moved
    }

    /// Deliver up to `quota` queued frames. The backlog lock is dropped around
    /// every delivery: receive processing transmits (ACKs, ICMP errors, ARP
    /// replies) and those transmits enqueue straight back here.
    /// # C: O(quota frames)
    fn process_backlog(&self, quota: usize) -> usize {
        let mut work = 0;
        while work < quota {
            let Some(item) = self.softnet_this_cpu().lock().dequeue() else { break };
            self.deliver_backlog_item(item);
            work += 1;
        }
        work
    }

    /// Deliver one queued frame under a freshly acquired ingress lease. A
    /// device that went down while the frame sat queued fails the acquire and
    /// the frame is dropped — the reference discards a backlog whose device is
    /// no longer running rather than delivering into a retired generation.
    /// # C: O(1) + protocol delivery
    fn deliver_backlog_item(&self, item: BacklogItem) {
        let lease = match item.generation {
            Some(generation) => self.ifaces.acquire_ingress_generation(item.iface, generation),
            None => self.ifaces.acquire_ingress(item.iface),
        };
        let Some(lease) = lease else {
            self.softnet_this_cpu().lock().note_dropped(1);
            return;
        };
        match item.packet {
            BacklogPacket::L3(pkt) => self.deliver_loopback_pkt_in(&lease, pkt),
            BacklogPacket::Ethernet { pkt, metadata } => {
                if self.deliver_ethernet_meta_in(&lease, pkt.data(), metadata).is_err() {
                    lease.device().record_rx_error();
                }
            }
        }
    }

    /// True while any poll-list device still holds frames. # C: O(N poll entries)
    fn rx_sources_pending(&self) -> bool {
        let mut list = self.rx_poll.lock();
        list.retain(|e| e.dev.strong_count() > 0);
        list.iter().any(|e| e.dev.upgrade().is_some_and(|d| d.rx_len() != 0))
    }

    /// Nothing queued on this CPU. # C: O(1)
    fn backlog_empty(&self) -> bool { self.softnet_this_cpu().lock().is_empty() }

    /// One NET_RX pass: poll the sources, then deliver in weight-sized slices
    /// until the budget or the work runs out. Returns true when the budget ran
    /// out first — the caller re-raises so the remainder runs on a later pass
    /// instead of holding this CPU indefinitely.
    /// # Ctx: NET_RX bottom half
    /// # C: O(NETDEV_BUDGET frames)
    pub fn do_net_rx(&self) -> bool {
        let mut budget = NETDEV_BUDGET;
        loop {
            let moved = self.poll_rx_sources();
            let quota = ::core::cmp::min(budget, DEV_RX_WEIGHT);
            let work = self.process_backlog(quota);
            budget -= work;
            if budget == 0 { break; }
            if work == 0 && moved == 0 { return false; }
        }
        if self.backlog_empty() && !self.rx_sources_pending() { return false; }
        self.softnet_this_cpu().lock().note_time_squeeze();
        true
    }

    /// Live `/proc/net/softnet_stat` rows, one per CPU slot. # C: O(N cpus)
    pub fn softnet_rows(&self) -> Vec<SoftnetRow> {
        self.softnet.iter().map(|sd| sd.lock().row()).collect()
    }

    /// Discard this CPU's queued frames, accounting each as a drop. # C: O(N queued)
    #[cfg(any(test, feature = "hosted"))]
    pub fn purge_backlog(&self) { self.softnet_this_cpu().lock().purge(); }
}
