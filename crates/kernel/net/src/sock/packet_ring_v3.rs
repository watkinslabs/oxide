use super::*;
use core::sync::atomic::Ordering;

const BLOCK_DESC_LEN: u32 = 48;
const V3_ALIGN: u32 = 8;
const HEADER_GAP: u32 = 16;
const DEFAULT_RETIRE_MS: u64 = 8;
const NS_PER_MS: u64 = 1_000_000;
const NS_PER_SEC: u64 = 1_000_000_000;
const BLOCK_STATUS_OFF: u64 = 8;

pub(crate) struct PacketV3State {
    active: u32,
    sequence: u64,
    next: u32,
    previous: Option<u32>,
    frozen: bool,
    interval_ns: u64,
    deadline_ns: u64,
}

pub(crate) struct V3Publish { pub published: bool, pub froze: bool }

fn align(value: u32, by: u32) -> Option<u32> {
    value.checked_add(by - 1).map(|v| v & !(by - 1))
}

fn write_u16(ring: &PacketRingMemory, off: u64, value: u16) -> bool {
    ring.write(off, &value.to_ne_bytes())
}

fn write_u32(ring: &PacketRingMemory, off: u64, value: u32) -> bool {
    ring.write(off, &value.to_ne_bytes())
}

fn write_u64(ring: &PacketRingMemory, off: u64, value: u64) -> bool {
    ring.write(off, &value.to_ne_bytes())
}

fn block_base(state: &PacketV3State, ring: &PacketRingMemory) -> u64 {
    state.active as u64 * ring.layout().request.block_size as u64
}

fn block_status(state: &PacketV3State, ring: &PacketRingMemory) -> Option<u32> {
    ring.load_u32(block_base(state, ring) + BLOCK_STATUS_OFF)
}

fn write_time(ring: &PacketRingMemory, off: u64, now_ns: u64) -> bool {
    write_u32(ring, off, (now_ns / NS_PER_SEC) as u32)
        && write_u32(ring, off + 4, (now_ns % NS_PER_SEC) as u32)
}

impl PacketV3State {
    /// Initialize and open Linux's first V3 block. # C: O(1)
    pub(crate) fn new(ring: &PacketRingMemory, monotonic_ns: u64, realtime_ns: u64) -> Self {
        let timeout = ring.layout().request.retire_block_timeout as u64;
        let interval_ns = timeout.max(if timeout == 0 { DEFAULT_RETIRE_MS } else { 0 }) * NS_PER_MS;
        let mut state = Self { active: 0, sequence: 1, next: 0, previous: None,
            frozen: false, interval_ns, deadline_ns: monotonic_ns.saturating_add(interval_ns) };
        state.open(ring, realtime_ns);
        state
    }

    fn first_offset(&self, ring: &PacketRingMemory) -> Option<u32> {
        let private = ring.layout().request.private_size as u16 as u32;
        BLOCK_DESC_LEN.checked_add(align(private, V3_ALIGN)?)
    }

    fn open(&mut self, ring: &PacketRingMemory, now_ns: u64) -> bool {
        let Some(first) = self.first_offset(ring) else { return false; };
        let base = block_base(self, ring);
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        self.next = first;
        self.previous = None;
        self.frozen = false;
        write_u32(ring, base, crate::uapi::TPACKET_V3 as u32)
            && write_u32(ring, base + 4, BLOCK_DESC_LEN)
            && write_u32(ring, base + 12, 0)
            && write_u32(ring, base + 16, first)
            && write_u32(ring, base + 20, first)
            && write_u64(ring, base + 24, sequence)
            && write_time(ring, base + 32, now_ns)
    }

    fn retire(&mut self, ring: &PacketRingMemory, losing: bool, timeout: bool,
              now_ns: u64) -> bool {
        let previous = self.previous.unwrap_or(self.next);
        let base = block_base(self, ring);
        let _ = write_u32(ring, base + previous as u64, 0);
        if self.previous.is_some() {
            let mut timestamp = [0u8; 8];
            if ring.copy(base + previous as u64 + 4, &mut timestamp) {
                let _ = ring.write(base + 40, &timestamp);
            }
        } else { let _ = write_time(ring, base + 40, now_ns); }
        let mut status = crate::uapi::TP_STATUS_USER;
        if losing { status |= crate::uapi::TP_STATUS_LOSING; }
        if timeout { status |= crate::uapi::TP_STATUS_BLK_TMO; }
        let published = ring.store_u32(base + BLOCK_STATUS_OFF, status);
        self.active = (self.active + 1) % ring.layout().request.block_nr;
        published
    }

    fn dispatch(&mut self, ring: &PacketRingMemory, now_ns: u64) -> bool {
        if block_status(self, ring) != Some(crate::uapi::TP_STATUS_KERNEL) {
            self.frozen = true;
            return false;
        }
        self.open(ring, now_ns)
    }
}

fn offsets(input: &PacketRingInput<'_>, reserve: u32) -> Option<(u32, u32)> {
    let header = align(crate::uapi::TPACKET_V3_HEADER_LEN + crate::uapi::SOCKADDR_LL_LEN,
        crate::uapi::TPACKET_ALIGNMENT)?;
    let mac_len = if input.datagram { 0 } else { input.aux.net as u32 };
    let net = if input.datagram {
        header.checked_add(HEADER_GAP)?.checked_add(reserve)?
    } else {
        align((crate::uapi::TPACKET_V3_HEADER_LEN + crate::uapi::SOCKADDR_LL_LEN)
            .checked_add(mac_len.max(HEADER_GAP))?, crate::uapi::TPACKET_ALIGNMENT)?
            .checked_add(reserve)?
    };
    let mac = net.checked_sub(mac_len)?;
    let vnet = input.aux.vnet_hdr_size as u32;
    Some((mac.checked_add(vnet)?, net.checked_add(vnet)?))
}

fn write_sockaddr(ring: &PacketRingMemory, off: u64, input: &PacketRingInput<'_>) -> bool {
    let mut address = [0u8; crate::uapi::SOCKADDR_LL_LEN as usize];
    address[0..2].copy_from_slice(&AF_PACKET.to_ne_bytes());
    address[2..4].copy_from_slice(&input.addr.protocol.to_be_bytes());
    address[4..8].copy_from_slice(&input.addr.ifindex.to_ne_bytes());
    address[8..10].copy_from_slice(&input.addr.hatype.to_ne_bytes());
    address[10] = input.addr.pkttype;
    address[11] = input.addr.halen;
    address[12..20].copy_from_slice(&input.addr.addr);
    ring.write(off + crate::uapi::TPACKET_V3_HEADER_LEN as u64, &address)
}

/// Publish one packet into Linux's active V3 block. # C: O(payload)
pub(crate) fn publish_v3(state: &mut Option<PacketV3State>, ring: &PacketRingMemory,
                         input: &PacketRingInput<'_>, losing: bool, now_ns: u64) -> V3Publish {
    let failed = V3Publish { published: false, froze: false };
    let Some(state) = state.as_mut() else { return failed; };
    if state.frozen && !state.dispatch(ring, now_ns) { return failed; }
    let Some((mac, net)) = offsets(input, ring.layout().reserve) else { return failed; };
    if net > u16::MAX as u32 || mac > u16::MAX as u32 { return failed; }
    let first = state.first_offset(ring).unwrap_or(ring.layout().request.block_size);
    let max_frame = ring.layout().request.block_size.saturating_sub(first);
    let snaplen = (input.payload.len().min(input.aux.snaplen as usize) as u32)
        .min(max_frame.saturating_sub(mac));
    let Some(record_len) = align(mac.saturating_add(snaplen), V3_ALIGN) else { return failed; };
    if state.next.saturating_add(record_len) >= ring.layout().request.block_size {
        let _ = state.retire(ring, losing, false, now_ns);
        if !state.dispatch(ring, now_ns) {
            return V3Publish { published: false, froze: true };
        }
    }
    let base = block_base(state, ring);
    let packet = state.next;
    let off = base + packet as u64;
    let status = input.aux.status | input.aux.timestamp_status;
    let timestamp_ns = input.aux.timestamp_ns.unwrap_or(now_ns);
    let vnet = input.aux.vnet_hdr_size as u32;
    let feature = ring.layout().request.feature_request & crate::uapi::TP_FT_REQ_FILL_RXHASH != 0;
    let header = write_u32(ring, off, record_len)
        && write_time(ring, off + 4, timestamp_ns)
        && write_u32(ring, off + 12, snaplen)
        && write_u32(ring, off + 16, input.aux.len)
        && write_u32(ring, off + 20, status)
        && write_u16(ring, off + 24, mac as u16)
        && write_u16(ring, off + 26, net as u16)
        && write_u32(ring, off + 28, if feature { input.rxhash } else { 0 })
        && write_u32(ring, off + 32, input.aux.vlan_tci as u32)
        && write_u16(ring, off + 36, input.aux.vlan_tpid)
        && ring.write(off + 38, &[0; 10])
        && write_sockaddr(ring, off, input)
        && (vnet == 0 || ring.write(off + (mac - VNET_HDR_SIZE as u32) as u64,
            &input.aux.vnet_header[..VNET_HDR_SIZE]))
        && ring.write(off + mac as u64, &input.payload[..snaplen as usize]);
    if !header { return failed; }
    let packets = ring.load_u32(base + 12).unwrap_or(0).wrapping_add(1);
    let used = ring.load_u32(base + 20).unwrap_or(first).saturating_add(record_len);
    let _ = write_u32(ring, base + 12, packets);
    let _ = write_u32(ring, base + 20, used);
    state.previous = Some(packet);
    state.next = state.next.saturating_add(record_len);
    V3Publish { published: true, froze: false }
}

/// Classify V3 fanout room by quarter-block lookahead. # C: O(1)
pub(crate) fn room_v3(state: &PacketV3State, ring: &PacketRingMemory) -> PacketRoom {
    let count = ring.layout().request.block_nr;
    let future = (state.active + (count >> 2)) % count;
    let future_off = future as u64 * ring.layout().request.block_size as u64 + BLOCK_STATUS_OFF;
    if ring.load_u32(future_off) == Some(crate::uapi::TP_STATUS_KERNEL) { PacketRoom::Normal }
    else if block_status(state, ring) == Some(crate::uapi::TP_STATUS_KERNEL) { PacketRoom::Low }
    else { PacketRoom::None }
}

/// Report previous-block V3 poll readiness. # C: O(1)
pub(crate) fn readable_v3(state: &PacketV3State, ring: &PacketRingMemory) -> bool {
    let count = ring.layout().request.block_nr;
    let previous = if state.active == 0 { count - 1 } else { state.active - 1 };
    let off = previous as u64 * ring.layout().request.block_size as u64 + BLOCK_STATUS_OFF;
    ring.load_u32(off).is_some_and(|status| status != crate::uapi::TP_STATUS_KERNEL)
}

/// Retire due V3 blocks across live packet sockets. # C: O(sockets)
pub(crate) fn service_packet_ring_timers(now_ns: u64) {
    let sockets = {
        // `lock_bh`: `deliver` takes this registry from the packet-RX SOFTIRQ,
        // so a plain acquisition in process context lets that softirq land on
        // this CPU mid-hold and spin forever (`06§3.1`, `skizm.md` Step 3e-bh).
        // Safe to release here — the guard is scoped to this block, so
        // `local_bh_enable`'s inline drain holds no other lock.
        let mut registry = PACKET_REGISTRY.lock_bh::<sched::bh::SchedBh>();
        registry.retain(|weak| weak.upgrade().is_some());
        registry.iter().filter_map(alloc::sync::Weak::upgrade).collect::<Vec<_>>()
    };
    for socket in sockets {
        if socket.released.load(Ordering::Acquire) { continue; }
        if socket.service_packet_v3_timer(now_ns) {
            #[cfg(target_os = "oxide-kernel")]
            socket.recv_waiters.wake_all();
            socket.poll_subs.notify();
        }
    }
}

impl InetSocket {
    /// Service one socket's V3 retirement deadline. # C: O(1)
    pub(crate) fn service_packet_v3_timer(&self, now_ns: u64) -> bool {
        let mut rings = self.packet_rings.lock();
        let Some(ring) = rings.rx.clone() else { return false; };
        let Some(state) = rings.rx_v3.as_mut() else { return false; };
        if now_ns < state.deadline_ns { return false; }
        state.deadline_ns = now_ns.saturating_add(state.interval_ns);
        let kind = self.kind.lock();
        let SockKind::Packet { rx, .. } = &*kind else { return false; };
        let mut queue = rx.lock();
        if state.frozen {
            if block_status(state, &ring) == Some(crate::uapi::TP_STATUS_KERNEL) {
                let _ = state.open(&ring, vfs::inode_times::realtime_now_ns());
            }
            return false;
        }
        if state.previous.is_none() { return false; }
        let realtime_ns = vfs::inode_times::realtime_now_ns();
        let retired = state.retire(&ring, queue.has_drops(), true, realtime_ns);
        if !state.dispatch(&ring, realtime_ns) {
            queue.account_freeze();
        }
        retired
    }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
/// Read x86 monotonic time for V3 deadline initialization. # C: O(1)
pub(crate) fn packet_monotonic_ns() -> u64 {
    use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0
}
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
/// Read Arm monotonic time for V3 deadline initialization. # C: O(1)
pub(crate) fn packet_monotonic_ns() -> u64 {
    use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0
}
#[cfg(not(target_os = "oxide-kernel"))]
/// Return deterministic hosted V3 deadline origin. # C: O(1)
pub(crate) fn packet_monotonic_ns() -> u64 { 0 }
