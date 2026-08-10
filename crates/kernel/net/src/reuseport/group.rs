// The reuseport group object itself: one program slot shared by every member
// of a bind key, plus the member bookkeeping the detach ladder branches on.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use sync::{Socket as SockLockClass, Spinlock};
use syscall::errno::Errno;

use super::slot::SlotCell;
use crate::bpf_filter::FilterProgram;

/// One SO_REUSEPORT bind key's shared selection state.
pub struct ReuseportGroup {
    prog: Spinlock<Option<Arc<FilterProgram>>, SockLockClass>,
    /// Members are held weakly through their own `sk_reuseport_cb` cells, so a
    /// closed socket leaves the group when its cell is dropped.
    members: Spinlock<Vec<Weak<SlotCell>>, SockLockClass>,
    has_conns: AtomicBool,
    closed_socks: AtomicUsize,
    /// Linux `sock_reuseport.bind_inany`, published to a selection program.
    bind_inany: AtomicBool,
}

/// One arriving packet, as a reuseport group's selection sees it.
pub struct SelectInput<'a> {
    /// Flow hash over the four tuple: the value the group's own distribution
    /// uses when no program answers.
    pub hash: u32,
    pub members_len: usize,
    /// Packet bytes from the transport header onward.
    pub transport: &'a [u8],
    /// Length of that transport header, which is what a classic filter's
    /// data pointer is advanced by before the program runs.
    pub hdr_len: usize,
    /// Link-layer protocol in host order, e.g. `ETH_P_IP`.
    pub eth_protocol: u16,
    /// Transport protocol, e.g. `IPPROTO_TCP`.
    pub ip_protocol: u8,
}

/// What a group's selection produced for one packet.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Select {
    /// No program answered; the caller's flow-hash distribution decides.
    Hash,
    /// This member of the group takes the packet.
    Member(usize),
    /// The selection program refused the packet.
    Drop,
}

/// One UDP endpoint group's selection over a received datagram, with the
/// group's own flow-hash distribution folded in. `None` is a datagram the
/// selection program refused, which reaches no endpoint. Shared by both
/// families: only the link-layer protocol differs between them.
/// # C: O(program)
pub fn select_udp(slot: &super::slot::ReuseportSlot, hash: u32, members_len: usize,
                  datagram: &[u8], eth_protocol: u16) -> Option<usize> {
    super::slot::group(slot)
        .map_or(Select::Hash, |group| {
            group.select(SelectInput {
                hash, members_len, transport: datagram,
                hdr_len: crate::udp::UDP_HDR_LEN, eth_protocol,
                ip_protocol: crate::addr::IpProto::Udp as u8,
            })
        })
        .index(hash, members_len)
}

impl Select {
    /// The member a caller takes, with the group's own flow-hash
    /// distribution folded in as the answer for every packet no program
    /// chose. `None` is a packet the selection program refused, which the
    /// caller delivers to nobody. # C: O(1)
    pub fn index(self, hash: u32, members_len: usize) -> Option<usize> {
        match self {
            Select::Member(index) => Some(index),
            Select::Hash => (members_len != 0).then(|| hash as usize % members_len),
            Select::Drop => None,
        }
    }
}

impl ReuseportGroup {
    /// Build an empty group with no program and no members. # C: O(1)
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            prog: Spinlock::new(None),
            members: Spinlock::new(Vec::new()),
            has_conns: AtomicBool::new(false),
            closed_socks: AtomicUsize::new(0),
            bind_inany: AtomicBool::new(false),
        })
    }

    /// Replace the selection program; a previous program is released. # C: O(1)
    pub fn attach_prog(&self, prog: FilterProgram) {
        *self.prog.lock() = Some(Arc::new(prog));
    }

    /// Drop the selection program, distinguishing an absent one. # C: O(1)
    pub fn detach_prog(&self) -> Result<(), Errno> {
        let mut slot = self.prog.lock();
        if slot.is_none() { return Err(Errno::Enoent); }
        *slot = None;
        Ok(())
    }

    /// Observe whether a selection program is installed. # C: O(1)
    pub fn has_prog(&self) -> bool { self.prog.lock().is_some() }

    /// Run the selection program over one arriving packet.
    ///
    /// Two program flavours share this slot and are not run the same way,
    /// exactly as the reference distinguishes them:
    ///
    ///   * A classic filter answers with the member index directly, and sees
    ///     the packet with its data pointer already advanced past the
    ///     transport header — the payload, not the header.
    ///   * A `BPF_PROG_TYPE_SK_REUSEPORT` program answers with an action and
    ///     reads its input as `sk_reuseport_md`, whose data begins AT the
    ///     transport header. It names the member it wants through a socket
    ///     map rather than through its return value, so a program that names
    ///     none leaves the group on its hash distribution and one that
    ///     answers `SK_DROP` refuses the packet outright.
    ///
    /// An index at or past the member count, an empty member set, and an
    /// absent program all leave the caller on the hash distribution.
    /// # C: O(program)
    pub fn select(&self, input: SelectInput<'_>) -> Select {
        if input.members_len == 0 { return Select::Hash; }
        let Some(prog) = self.prog.lock().clone() else { return Select::Hash; };
        match prog.kind {
            crate::bpf_filter::FilterKind::SkReuseport => {
                let action = crate::bpf_filter::run_reuseport_program(&prog.insns,
                    crate::bpf_filter::ReuseportContext {
                        packet: input.transport,
                        eth_protocol: input.eth_protocol,
                        ip_protocol: input.ip_protocol,
                        bind_inany: self.bind_inany(),
                        hash: input.hash,
                    });
                if action == crate::bpf_filter::SK_DROP { Select::Drop } else { Select::Hash }
            }
            _ => {
                let payload = input.transport.get(input.hdr_len..).unwrap_or(&[]);
                let index = crate::bpf_filter::run_program(&prog, payload) as usize;
                if index < input.members_len { Select::Member(index) } else { Select::Hash }
            }
        }
    }

    /// Whether any member of this group was bound to a wildcard address.
    /// Sticky: the reference raises it and never lowers it. # C: O(1)
    pub fn bind_inany(&self) -> bool { self.bind_inany.load(Ordering::Acquire) }

    /// Record that a socket joining this group was bound to a wildcard
    /// address. # C: O(1)
    pub fn note_bind_inany(&self, inany: bool) {
        if inany { self.bind_inany.store(true, Ordering::Release); }
    }

    /// Register one member cell. # C: O(N members)
    pub fn add_member(&self, member: &Arc<SlotCell>) {
        let mut members = self.members.lock();
        members.retain(|weak| weak.strong_count() != 0);
        if members.iter().any(|weak| weak.as_ptr() == Arc::as_ptr(member)) { return; }
        members.push(Arc::downgrade(member));
    }

    /// Remove one member cell. # C: O(N members)
    pub fn remove_member(&self, member: &Arc<SlotCell>) {
        let mut members = self.members.lock();
        members.retain(|weak| weak.strong_count() != 0 && weak.as_ptr() != Arc::as_ptr(member));
    }

    /// Live member count after dropping departed sockets. # C: O(N members)
    pub fn num_socks(&self) -> usize {
        let mut members = self.members.lock();
        members.retain(|weak| weak.strong_count() != 0);
        members.len()
    }

    /// Members retained past their socket's shutdown. # C: O(1)
    pub fn num_closed_socks(&self) -> usize { self.closed_socks.load(Ordering::Acquire) }

    /// Record one member kept after shutdown removed it from its bind key. # C: O(1)
    pub fn note_closed_sock(&self) { self.closed_socks.fetch_add(1, Ordering::AcqRel); }

    /// Release one shutdown member's retained slot. # C: O(1)
    pub fn release_closed_sock(&self) {
        let _ = self.closed_socks.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |used| used.checked_sub(1));
    }

    /// Whether any member has taken a connected peer. # C: O(1)
    pub fn has_conns(&self) -> bool { self.has_conns.load(Ordering::Acquire) }

    /// Latch that a member connected, which pins established flows. # C: O(1)
    pub fn set_has_conns(&self) { self.has_conns.store(true, Ordering::Release); }
}
