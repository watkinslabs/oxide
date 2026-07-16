use super::*;
use alloc::sync::{Arc, Weak};
use crate::bpf_filter::{FilterContext, FilterProgram, SocketFilter};
use core::sync::atomic::Ordering;

const FANOUT_MODE_MASK: u16 = 0x00ff;
const FANOUT_FLAGS_MASK: u16 = crate::uapi::PACKET_FANOUT_FLAG_ROLLOVER
    | crate::uapi::PACKET_FANOUT_FLAG_UNIQUEID
    | crate::uapi::PACKET_FANOUT_FLAG_IGNORE_OUTGOING
    | crate::uapi::PACKET_FANOUT_FLAG_DEFRAG;
const ROLLOVER_HISTORY_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketFanoutRequest {
    pub id: u16,
    pub type_flags: u16,
    pub max_num_members: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketRolloverStatistics {
    pub all: u64,
    pub huge: u64,
    pub failed: u64,
}

struct PacketRolloverState {
    next: usize,
    statistics: PacketRolloverStatistics,
    history: [u32; ROLLOVER_HISTORY_LEN],
    victim: usize,
}

pub struct PacketFanoutMember {
    socket: Weak<InetSocket>,
    group: Arc<PacketFanoutGroup>,
    rollover: Option<Spinlock<PacketRolloverState, SockLockClass>>,
    delivery: Spinlock<(), SockLockClass>,
}

struct PacketFanoutState {
    members: Vec<Weak<PacketFanoutMember>>,
    rr: u32,
    random: u64,
    filter: Arc<SocketFilter>,
}

pub(crate) struct PacketFanoutGroup {
    net_ns: u64,
    id: u16,
    mode: u8,
    flags: u16,
    max_members: u32,
    protocol: u16,
    ifindex: u32,
    state: Spinlock<PacketFanoutState, SockLockClass>,
}

static PACKET_FANOUT_GROUPS: Spinlock<Vec<Arc<PacketFanoutGroup>>, SockLockClass>
    = Spinlock::new(Vec::new());
static PACKET_FANOUT_NEXT_ID: Spinlock<u16, SockLockClass> = Spinlock::new(0);

fn valid_mode(mode: u8) -> bool {
    matches!(mode, crate::uapi::PACKET_FANOUT_HASH | crate::uapi::PACKET_FANOUT_LB
        | crate::uapi::PACKET_FANOUT_CPU | crate::uapi::PACKET_FANOUT_ROLLOVER
        | crate::uapi::PACKET_FANOUT_RND | crate::uapi::PACKET_FANOUT_QM
        | crate::uapi::PACKET_FANOUT_CBPF | crate::uapi::PACKET_FANOUT_EBPF)
}

fn unique_id(groups: &[Arc<PacketFanoutGroup>], net_ns: u64) -> crate::NetResult<u16> {
    let mut next = PACKET_FANOUT_NEXT_ID.lock();
    let first = *next;
    loop {
        let candidate = *next;
        *next = next.wrapping_add(1);
        if !groups.iter().any(|group| group.net_ns == net_ns && group.id == candidate) {
            return Ok(candidate);
        }
        if *next == first { return Err(crate::NetError::Enomem); }
    }
}

impl InetSocket {
    /// Join or create one Linux AF_PACKET fanout group. # C: O(groups + members)
    pub fn join_packet_fanout(self: &Arc<Self>, mut request: PacketFanoutRequest)
        -> crate::NetResult<()>
    {
        let mode = (request.type_flags & FANOUT_MODE_MASK) as u8;
        let mut flags = request.type_flags & !FANOUT_MODE_MASK;
        if !valid_mode(mode) || flags & !FANOUT_FLAGS_MASK != 0
            || (mode == crate::uapi::PACKET_FANOUT_ROLLOVER
                && flags & crate::uapi::PACKET_FANOUT_FLAG_ROLLOVER != 0)
        { return Err(crate::NetError::Einval); }
        let mut membership = self.packet_fanout.lock();
        if membership.is_some() { return Err(crate::NetError::Ealready); }
        let (protocol, ifindex) = {
            let kind = self.kind.lock();
            let SockKind::Packet { protocol, ifindex, .. } = &*kind else {
                return Err(crate::NetError::Enoprotoopt);
            };
            (protocol.load(Ordering::Acquire), ifindex.load(Ordering::Acquire))
        };
        if protocol == 0 { return Err(crate::NetError::Einval); }
        let mut groups = PACKET_FANOUT_GROUPS.lock();
        if flags & crate::uapi::PACKET_FANOUT_FLAG_UNIQUEID != 0 {
            if request.id != 0 { return Err(crate::NetError::Einval); }
            request.id = unique_id(&groups, self.net_ns())?;
            flags &= !crate::uapi::PACKET_FANOUT_FLAG_UNIQUEID;
        }
        let existing = groups.iter().find(|group| {
            group.net_ns == self.net_ns() && group.id == request.id
        }).cloned();
        let group = match existing {
            Some(group) => {
                if group.mode != mode || group.flags != flags || group.protocol != protocol
                    || group.ifindex != ifindex
                    || (request.max_num_members != 0
                        && request.max_num_members != group.max_members)
                { return Err(crate::NetError::Einval); }
                group
            }
            None => {
                if request.max_num_members > crate::uapi::PACKET_FANOUT_MAX {
                    return Err(crate::NetError::Einval);
                }
                let max_members = if request.max_num_members == 0 {
                    crate::uapi::PACKET_FANOUT_LEGACY_MAX
                } else { request.max_num_members };
                let group = Arc::new(PacketFanoutGroup {
                    net_ns: self.net_ns(), id: request.id, mode, flags, max_members,
                    protocol, ifindex,
                    state: Spinlock::new(PacketFanoutState {
                        members: Vec::new(), rr: 0,
                        random: ((self.net_ns() << 16) ^ request.id as u64).wrapping_add(1),
                        filter: Arc::new(SocketFilter::new()),
                    }),
                });
                groups.push(group.clone());
                group
            }
        };
        let rollover = mode == crate::uapi::PACKET_FANOUT_ROLLOVER
            || flags & crate::uapi::PACKET_FANOUT_FLAG_ROLLOVER != 0;
        let member = Arc::new(PacketFanoutMember {
            socket: Arc::downgrade(self), group: group.clone(),
            rollover: rollover.then(|| Spinlock::new(PacketRolloverState {
                next: 0, statistics: PacketRolloverStatistics::default(),
                history: [0; ROLLOVER_HISTORY_LEN], victim: 0,
            })),
            delivery: Spinlock::new(()),
        });
        let mut state = group.state.lock();
        state.members.retain(|weak| weak.upgrade().is_some());
        if state.members.len() >= group.max_members as usize {
            return Err(crate::NetError::Enospc);
        }
        state.members.push(Arc::downgrade(&member));
        drop(state);
        *membership = Some(member);
        register_packet(self);
        Ok(())
    }

    /// Return whether this packet socket is currently grouped. # C: O(1)
    pub fn packet_in_fanout(&self) -> bool { self.packet_fanout.lock().is_some() }

    /// Bind packet protocol/device atomically against fanout join. # C: O(1)
    pub fn bind_packet(self: &Arc<Self>, ifindex: u32, protocol: u16) -> crate::NetResult<()> {
        let membership = self.packet_fanout.lock();
        if membership.is_some() { return Err(crate::NetError::Einval); }
        let kind = self.kind.lock();
        let SockKind::Packet { ifindex: bound, protocol: selected, .. } = &*kind else {
            return Err(crate::NetError::Einval);
        };
        bound.store(ifindex, Ordering::Release);
        selected.store(protocol, Ordering::Release);
        drop(kind);
        drop(membership);
        register_packet(self);
        Ok(())
    }

    /// Encode Linux `PACKET_FANOUT` get value, or zero when ungrouped. # C: O(1)
    pub fn packet_fanout_value(&self) -> crate::NetResult<i32> {
        if !matches!(*self.kind.lock(), SockKind::Packet { .. }) {
            return Err(crate::NetError::Enoprotoopt);
        }
        let membership = self.packet_fanout.lock();
        let Some(member) = membership.as_ref() else { return Ok(0); };
        let group = &member.group;
        Ok(group.id as i32 | (group.mode as i32) << 16 | ((group.flags >> 8) as i32) << 24)
    }

    /// Return the active Linux fanout selector mode. # C: O(1)
    pub fn packet_fanout_mode(&self) -> crate::NetResult<u8> {
        let Some(member) = self.packet_fanout.lock().clone() else {
            return Err(crate::NetError::Einval);
        };
        Ok(member.group.mode)
    }

    /// Replace the shared CBPF/EBPF fanout selector. # C: O(program bytes)
    pub fn set_packet_fanout_data(&self, program: FilterProgram) -> crate::NetResult<()> {
        if self.bpf_filter.is_locked() { return Err(crate::NetError::Eperm); }
        let Some(member) = self.packet_fanout.lock().clone() else {
            return Err(crate::NetError::Einval);
        };
        let expected = if member.group.mode == crate::uapi::PACKET_FANOUT_CBPF {
            crate::bpf_filter::FilterKind::Classic
        } else if member.group.mode == crate::uapi::PACKET_FANOUT_EBPF {
            crate::bpf_filter::FilterKind::Ebpf
        } else { return Err(crate::NetError::Einval); };
        if program.kind != expected { return Err(crate::NetError::Einval); }
        let group = member.group.clone();
        let result = group.state.lock().filter.attach(program)
            .map_err(|_| crate::NetError::Eperm);
        result
    }

    /// Read non-destructive Linux rollover counters. # C: O(1)
    pub fn packet_rollover_statistics(&self) -> crate::NetResult<PacketRolloverStatistics> {
        let Some(member) = self.packet_fanout.lock().clone() else {
            return Err(crate::NetError::Einval);
        };
        let Some(rollover) = member.rollover.as_ref() else { return Err(crate::NetError::Einval); };
        let statistics = rollover.lock().statistics;
        Ok(statistics)
    }

    /// Unlink final-file packet fanout membership and delete an empty group. # C: O(groups + members)
    pub(crate) fn release_packet_fanout(&self) {
        let Some(member) = self.packet_fanout.lock().take() else { return; };
        let _delivery = member.delivery.lock();
        let mut groups = PACKET_FANOUT_GROUPS.lock();
        let mut state = member.group.state.lock();
        unlink_member(&mut state, &member);
        let empty = state.members.is_empty();
        drop(state);
        if empty { groups.retain(|group| !Arc::ptr_eq(group, &member.group)); }
    }

    /// Validate then relink one running fanout hook around ring replacement. # C: O(members)
    pub(crate) fn with_packet_fanout_relink<T, R, E>(&self,
        prepare: impl FnOnce() -> Result<Option<T>, E>, op: impl FnOnce(T) -> Result<R, E>)
        -> Result<Option<R>, E>
    {
        let membership = self.packet_fanout.lock();
        let Some(member) = membership.clone() else {
            let Some(value) = prepare()? else { return Ok(None); };
            return op(value).map(Some);
        };
        let _delivery = member.delivery.lock();
        let Some(value) = prepare()? else { return Ok(None); };
        unlink_member(&mut member.group.state.lock(), &member);
        let result = op(value);
        member.group.state.lock().members.push(Arc::downgrade(&member));
        drop(membership);
        result.map(Some)
    }
}

fn unlink_member(state: &mut PacketFanoutState, member: &Arc<PacketFanoutMember>) {
    if let Some(index) = state.members.iter().position(|weak| weak.upgrade()
        .is_some_and(|candidate| Arc::ptr_eq(&candidate, member)))
    { state.members.swap_remove(index); }
}

impl PacketFanoutGroup {
    pub(crate) fn ignores_outgoing(&self) -> bool {
        self.flags & crate::uapi::PACKET_FANOUT_FLAG_IGNORE_OUTGOING != 0
    }

    pub(crate) fn defrag(&self) -> bool {
        self.flags & crate::uapi::PACKET_FANOUT_FLAG_DEFRAG != 0
    }

    pub(crate) fn defragment(&self, packet: &[u8], network: usize) -> Option<Vec<u8>> {
        match packet.get(network).map(|byte| byte >> 4) {
            Some(4) => defragment_ipv4(self, packet, network),
            _ => Some(packet.to_vec()),
        }
    }

    pub(crate) fn select(&self, packet: &[u8], context: FilterContext<'_>, hash: u32,
                         cpu: u32, queue: u32, charge: usize)
        -> Option<Arc<PacketFanoutMember>>
    {
        let mut state = self.state.lock();
        let members = state.members.iter().filter_map(Weak::upgrade).collect::<Vec<_>>();
        let count = members.len();
        if count == 0 { return None; }
        let index = match self.mode {
            crate::uapi::PACKET_FANOUT_HASH =>
                ((hash as u64 * count as u64) >> 32) as usize,
            crate::uapi::PACKET_FANOUT_LB => {
                state.rr = state.rr.wrapping_add(1);
                state.rr as usize % count
            }
            crate::uapi::PACKET_FANOUT_CPU => cpu as usize % count,
            crate::uapi::PACKET_FANOUT_QM => queue as usize % count,
            crate::uapi::PACKET_FANOUT_RND => {
                state.random ^= state.random << 13;
                state.random ^= state.random >> 7;
                state.random ^= state.random << 17;
                state.random as usize % count
            }
            crate::uapi::PACKET_FANOUT_CBPF | crate::uapi::PACKET_FANOUT_EBPF => {
                if state.filter.is_attached() {
                    state.filter.verdict_with_context(context) as usize % count
                } else { 0 }
            }
            crate::uapi::PACKET_FANOUT_ROLLOVER => 0,
            _ => return None,
        };
        drop(state);
        if self.mode == crate::uapi::PACKET_FANOUT_ROLLOVER {
            return rollover(&members, 0, false, hash, charge);
        }
        if self.flags & crate::uapi::PACKET_FANOUT_FLAG_ROLLOVER != 0 {
            return rollover(&members, index, true, hash, charge);
        }
        let _ = packet;
        members.get(index).cloned()
    }
}

fn rollover(members: &[Arc<PacketFanoutMember>], selected: usize, try_selected: bool,
            hash: u32, charge: usize) -> Option<Arc<PacketFanoutMember>> {
    let origin = members.get(selected)?.clone();
    let selected_room = member_room(&origin, charge);
    let Some(rollover) = origin.rollover.as_ref() else { return Some(origin); };
    let mut state = rollover.lock();
    if try_selected {
        if selected_room == PacketRoom::Normal { return Some(origin.clone()); }
        if selected_room == PacketRoom::Low {
            let repeats = state.history.iter().filter(|entry| **entry == hash).count();
            let victim = state.victim % state.history.len();
            state.victim = state.victim.wrapping_add(1);
            state.history[victim] = hash;
            if repeats <= state.history.len() / 2 { return Some(origin.clone()); }
        }
    }
    let start = state.next.min(members.len() - 1);
    for offset in 0..members.len() {
        let index = (start + offset) % members.len();
        if index != selected && member_normal(&members[index], charge) {
            state.next = index;
            state.statistics.all = state.statistics.all.wrapping_add(1);
            if selected_room == PacketRoom::Low {
                state.statistics.huge = state.statistics.huge.wrapping_add(1);
            }
            return Some(members[index].clone());
        }
    }
    state.statistics.failed = state.statistics.failed.wrapping_add(1);
    drop(state);
    Some(origin)
}

fn member_room(member: &PacketFanoutMember, charge: usize) -> PacketRoom {
    let Some(socket) = member.socket.upgrade() else { return PacketRoom::None; };
    if let Some(room) = socket.packet_ring_room() { return room; }
    let kind = socket.kind.lock();
    let SockKind::Packet { rx, .. } = &*kind else { return PacketRoom::None; };
    let limit = socket.opts.rcvbuf.load(Ordering::Acquire).max(0) as usize;
    let room = rx.lock().room(charge, limit);
    room
}

fn member_normal(member: &PacketFanoutMember, charge: usize) -> bool {
    let Some(socket) = member.socket.upgrade() else { return false; };
    if let Some(room) = socket.packet_ring_room() { return room == PacketRoom::Normal; }
    let kind = socket.kind.lock();
    let SockKind::Packet { rx, .. } = &*kind else { return false; };
    let limit = socket.opts.rcvbuf.load(Ordering::Acquire).max(0) as usize;
    let queue = rx.lock();
    !queue.pressured() && queue.room(charge, limit) == PacketRoom::Normal
}

pub(crate) fn packet_fanout_membership(socket: &InetSocket)
    -> Option<Arc<PacketFanoutMember>>
{
    socket.packet_fanout.lock().clone()
}

pub(crate) fn packet_fanout_group(member: &PacketFanoutMember) -> Arc<PacketFanoutGroup> {
    member.group.clone()
}

pub(crate) fn with_packet_fanout_socket<T>(member: &Arc<PacketFanoutMember>,
    op: impl FnOnce(&Arc<InetSocket>) -> T) -> Option<(Arc<InetSocket>, T)>
{
    let socket = member.socket.upgrade()?;
    let current = socket.packet_fanout.lock();
    if !current.as_ref().is_some_and(|candidate| Arc::ptr_eq(candidate, member)) { return None; }
    let _delivery = member.delivery.lock();
    drop(current);
    if socket.released.load(Ordering::Acquire) { return None; }
    let result = op(&socket);
    Some((socket, result))
}

fn defragment_ipv4(group: &PacketFanoutGroup, packet: &[u8], network: usize)
    -> Option<Vec<u8>>
{
    if packet.len() < network + 20 { return None; }
    let ihl = ((packet[network] & 0x0f) as usize * 4).max(20);
    if packet.len() < network + ihl { return None; }
    let total = u16::from_be_bytes([packet[network + 2], packet[network + 3]]) as usize;
    if total < ihl || packet.len() < network + total { return None; }
    let frag = u16::from_be_bytes([packet[network + 6], packet[network + 7]]);
    let more = frag & 0x2000 != 0;
    let offset = (frag & 0x1fff) as usize * 8;
    if !more && offset == 0 { return Some(packet.to_vec()); }
    let key = crate::ipv4_reasm::ReasmKey {
        net_ns: group.net_ns, domain: group.id as u32 + 1,
        src: crate::Ipv4Addr::new(packet[network + 12], packet[network + 13],
            packet[network + 14], packet[network + 15]),
        dst: crate::Ipv4Addr::new(packet[network + 16], packet[network + 17],
            packet[network + 18], packet[network + 19]),
        proto: packet[network + 9],
        id: u16::from_be_bytes([packet[network + 4], packet[network + 5]]),
    };
    let prefix = (offset == 0).then_some(&packet[..network + ihl]);
    let (mut prefix, payload) = stack().ipv4_reasm.push_with_prefix(key,
        crate::stack::net_now_ns(), offset, prefix, &packet[network + ihl..network + total], more)?;
    let ip_len = ihl.checked_add(payload.len())?;
    if ip_len > u16::MAX as usize || prefix.len() < network + ihl { return None; }
    prefix[network + 2..network + 4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    prefix[network + 6..network + 8].copy_from_slice(&0u16.to_be_bytes());
    prefix[network + 10..network + 12].copy_from_slice(&0u16.to_be_bytes());
    let checksum = ipv4_checksum(&prefix[network..network + ihl]);
    prefix[network + 10..network + 12].copy_from_slice(&checksum.to_be_bytes());
    prefix.extend_from_slice(&payload);
    Some(prefix)
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else { (chunk[0] as u16) << 8 };
        sum = sum.wrapping_add(word as u32);
    }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}
