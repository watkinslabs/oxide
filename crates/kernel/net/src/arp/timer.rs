use super::*;

impl ArpCache {
    /// Advance unresolved IPv4 neighbours under Linux's bounded solicitation
    /// policy. The caller emits probes and completes failures after this lock
    /// is released. # C: O(N entries)
    pub(crate) fn tick(&self, now_ns: u64) -> ArpTick {
        let mut out = ArpTick { probes: Vec::new(), failed: Vec::new() };
        if self.closed.load(Ordering::Acquire) || now_ns == 0 { return out; }
        let mut entries = self.inner.lock();
        for (target_ip, entry) in entries.iter_mut() {
            if now_ns < entry.probe_deadline_ns { continue; }
            match entry.state {
                NudState::Incomplete => {
                    if entry.probes >= ARP_MCAST_SOLICIT {
                        fail(entry, &mut out);
                        continue;
                    }
                    let Some(job) = entry.pending.front() else { continue; };
                    entry.probes += 1;
                    entry.probe_deadline_ns = now_ns.saturating_add(ARP_RETRANS_TIME_NS);
                    out.probes.push(ArpProbe { lease: job.lease(), source_ip: entry.source_ip,
                        target_ip: *target_ip, destination: MacAddr::BROADCAST });
                }
                NudState::Delay | NudState::Probe => {
                    if entry.probes >= ARP_UCAST_SOLICIT {
                        fail(entry, &mut out);
                        continue;
                    }
                    let (Some(mac), Some(lease)) = (entry.mac, entry.probe_lease.clone()) else {
                        fail(entry, &mut out);
                        continue;
                    };
                    entry.state = NudState::Probe;
                    entry.probes += 1;
                    entry.probe_deadline_ns = now_ns.saturating_add(ARP_RETRANS_TIME_NS);
                    out.probes.push(ArpProbe { lease, source_ip: entry.source_ip,
                        target_ip: *target_ip, destination: mac });
                }
                NudState::Reachable | NudState::Stale | NudState::Failed => {}
            }
        }
        entries.retain(|_, entry| entry.state == NudState::Incomplete || entry.inserted_ns == 0
            || now_ns.saturating_sub(entry.inserted_ns) <= ARP_STALE_NS);
        out
    }
}

fn fail(entry: &mut ArpEntry, out: &mut ArpTick) {
    entry.state = NudState::Failed;
    entry.mac = None;
    entry.pending_bytes = 0;
    entry.probe_lease = None;
    out.failed.extend(entry.pending.drain(..));
}
