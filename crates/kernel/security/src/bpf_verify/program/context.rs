//! Program-context access rules, one profile per verified program type.
//!
//! A profile answers two questions: how many context bytes the runner
//! publishes, and whether one (offset, size, direction) triple is a legal
//! field access. Both answers are the verifier's only knowledge of the
//! context, so a field this kernel does not populate is refused at load
//! rather than read back as a zero the program would trust.

use crate::bpf::uapi;
use crate::bpf_lsm::{self, Hook};
use super::Profile;

/// `struct __sk_buff` field offsets. Named because every one of them is an
/// ABI position a compiled filter encodes directly in its instructions.
pub mod sk_buff {
    pub const LEN:             usize = 0;
    pub const PKT_TYPE:        usize = 4;
    pub const MARK:            usize = 8;
    pub const QUEUE_MAPPING:   usize = 12;
    pub const PROTOCOL:        usize = 16;
    pub const VLAN_PRESENT:    usize = 20;
    pub const VLAN_TCI:        usize = 24;
    pub const VLAN_PROTO:      usize = 28;
    pub const PRIORITY:        usize = 32;
    pub const INGRESS_IFINDEX: usize = 36;
    pub const IFINDEX:         usize = 40;
    pub const TC_INDEX:        usize = 44;
    /// `cb[5]`, the only writable region of a socket filter's context.
    pub const CB:              usize = 48;
    pub const CB_END:          usize = 68;
    pub const HASH:            usize = 68;
    pub const TC_CLASSID:      usize = 72;
    pub const DATA:            usize = 76;
    pub const DATA_END:        usize = 80;
    pub const NAPI_ID:         usize = 84;
    pub const FAMILY:          usize = 88;
    pub const REMOTE_IP4:      usize = 92;
    pub const LOCAL_IP4:       usize = 96;
    pub const REMOTE_IP6:      usize = 100;
    pub const LOCAL_IP6:       usize = 116;
    pub const REMOTE_PORT:     usize = 132;
    pub const LOCAL_PORT:      usize = 136;
    /// End of the contiguous `family`..`local_port` block.
    pub const LOCAL_PORT_END:  usize = 140;
    pub const DATA_META:       usize = 140;
    pub const FLOW_KEYS:       usize = 144;
    pub const TSTAMP:          usize = 152;
    pub const WIRE_LEN:        usize = 160;
    pub const GSO_SEGS:        usize = 164;
    pub const SK:              usize = 168;
    pub const GSO_SIZE:        usize = 176;
    pub const TSTAMP_TYPE:     usize = 180;
    /// 3 bytes of reserved padding after `tstamp_type`.
    pub const PADDING:         usize = 181;
    pub const HWTSTAMP:        usize = 184;
    pub const SIZE:            usize = 192;
    /// Word width of every `__u32` field.
    pub const WORD:            usize = 4;
    /// Width of the `__u64` and pointer-shaped members.
    pub const WIDE:            usize = 8;
}

/// `struct sk_reuseport_md` field offsets: the context a
/// `BPF_PROG_TYPE_SK_REUSEPORT` program receives when a bind key with more
/// than one member has to choose which of them takes an arriving packet.
/// Named for the same reason as the `__sk_buff` block above — a compiled
/// program encodes each offset directly.
pub mod sk_reuseport_md {
    /// Start of the directly addressable bytes, at the transport header.
    pub const DATA:         usize = 0;
    pub const DATA_END:     usize = 8;
    /// Packet length measured from the transport header.
    pub const LEN:          usize = 16;
    /// Link-layer protocol in network order, e.g. `ETH_P_IP`.
    pub const ETH_PROTOCOL: usize = 20;
    /// Transport protocol in host order, e.g. `IPPROTO_TCP`.
    pub const IP_PROTOCOL:  usize = 24;
    /// Whether the group was created for a wildcard-bound socket.
    pub const BIND_INANY:   usize = 28;
    /// Flow hash over the packet's four tuple.
    pub const HASH:         usize = 32;
    /// 4 bytes of padding before the pointer pair.
    pub const PADDING:      usize = 36;
    pub const SK:           usize = 40;
    pub const MIGRATING_SK: usize = 48;
    pub const SIZE:         usize = 56;
    /// Word width of every `__u32` member.
    pub const WORD:         usize = 4;
    /// Width of the pointer-shaped members.
    pub const WIDE:         usize = 8;
}

/// `struct bpf_perf_event_data`: the architecture's userspace register
/// view followed by the sample period and sampled address. Both supported
/// architectures expose 64-bit registers, but the register counts differ.
pub mod perf_event_data {
    pub const WORD: usize = 8;
    pub const X86_64_REGS_BYTES: usize = 21 * WORD;
    pub const AARCH64_REGS_BYTES: usize = 34 * WORD;

    #[cfg(target_arch = "x86_64")]
    pub const REGS_BYTES: usize = X86_64_REGS_BYTES;
    #[cfg(target_arch = "aarch64")]
    pub const REGS_BYTES: usize = AARCH64_REGS_BYTES;

    pub const SAMPLE_PERIOD: usize = REGS_BYTES;
    pub const ADDR: usize = SAMPLE_PERIOD + WORD;
    pub const SIZE: usize = ADDR + WORD;
}

/// Bytes of context this kernel publishes for a reuseport selection program.
pub const SK_REUSEPORT_CONTEXT_BYTES: usize = sk_reuseport_md::SIZE;

/// Bytes of context this kernel publishes for a socket filter. The whole
/// `struct __sk_buff` is materialised so that field admission is decided by
/// the field rules below rather than by where a buffer happens to stop;
/// every field those rules refuse is unreachable, so its bytes are never
/// observable.
pub const SK_FILTER_CONTEXT_BYTES: usize = sk_buff::SIZE;

/// Context window a cgroup program's pointer arithmetic may address.
const CGROUP_CONTEXT_BYTES: usize = 64;
const RAW_TRACEPOINT_CONTEXT_BYTES: usize = 12 * core::mem::size_of::<u64>();

/// Bytes of context an iterator program addresses: the iteration meta
/// record and the object of the current step. Every published target
/// declares the same two, so the shape belongs to the program type.
use crate::bpf::iter_context_bytes;

/// Upper bound on context-relative addressing for one program.
/// # C: O(1)
pub(super) fn context_size(profile: &Profile) -> usize {
    match (profile.prog_type, profile.hook) {
        (uapi::prog_type::SOCKET_FILTER, _) => SK_FILTER_CONTEXT_BYTES,
        (uapi::prog_type::SK_REUSEPORT, _) => SK_REUSEPORT_CONTEXT_BYTES,
        (uapi::prog_type::LSM, Some(hook)) => bpf_lsm::context_bytes(hook),
        (uapi::prog_type::TRACING, _) => iter_context_bytes(),
        (uapi::prog_type::RAW_TRACEPOINT | uapi::prog_type::RAW_TRACEPOINT_WRITABLE, _) =>
            RAW_TRACEPOINT_CONTEXT_BYTES,
        (uapi::prog_type::PERF_EVENT, _) => perf_event_data::SIZE,
        _ => CGROUP_CONTEXT_BYTES,
    }
}

/// Whether one context access is admitted for this program type.
/// # C: O(1)
pub(super) fn valid_context(
    profile: &Profile,
    offset: usize,
    size: usize,
    write: bool,
) -> bool {
    match profile.prog_type {
        uapi::prog_type::SOCKET_FILTER => sk_filter_access(offset, size, write),
        uapi::prog_type::SK_REUSEPORT => sk_reuseport_access(offset, size, write),
        uapi::prog_type::CGROUP_SKB =>
            !write && size == sk_buff::WORD
                && matches!(offset, sk_buff::LEN | sk_buff::PROTOCOL | sk_buff::IFINDEX),
        uapi::prog_type::CGROUP_SOCK_ADDR =>
            sock_addr_access(profile.expected_attach_type, offset, size, write),
        uapi::prog_type::LSM =>
            profile.hook.is_some_and(|hook| lsm_access(hook, offset, size, write)),
        uapi::prog_type::TRACING => iter_access(offset, size, write),
        uapi::prog_type::RAW_TRACEPOINT | uapi::prog_type::RAW_TRACEPOINT_WRITABLE =>
            !write && size != 0 && offset % size == 0,
        uapi::prog_type::PERF_EVENT => perf_event_access(offset, size, write),
        _ => false,
    }
}

/// Perf-event programs see a read-only native register word array followed
/// by two u64 fields. Linux permits narrow aligned reads only in the two u64
/// fields; register slots are read one native word at a time.
fn perf_event_access(offset: usize, size: usize, write: bool) -> bool {
    use perf_event_data as pe;
    if write || size == 0 || offset % size != 0 { return false; }
    if offset < pe::REGS_BYTES {
        return size == pe::WORD && within(offset, size, 0, pe::REGS_BYTES);
    }
    matches!(size, 1 | 2 | 4 | 8)
        && (within(offset, size, pe::SAMPLE_PERIOD, pe::ADDR)
            || within(offset, size, pe::ADDR, pe::SIZE))
}

/// LSM hook context: one register-wide slot per declared hook argument,
/// then the slot holding the return value the chain has produced so far.
/// A slot is read whole or not at all, nothing past the last slot is
/// addressable, and no slot is writable.
///
/// An argument slot holds a typed kernel pointer. This verifier proves no
/// field access through it, so a program may observe the slot's value and
/// may never follow it; a load through the loaded value is refused as an
/// access through a non-pointer.
/// # C: O(1)
fn lsm_access(hook: Hook, offset: usize, size: usize, write: bool) -> bool {
    !write && size == bpf_lsm::SLOT_BYTES && offset % bpf_lsm::SLOT_BYTES == 0
        && offset < bpf_lsm::context_bytes(hook)
}

/// Iterator context: the meta slot and the object slot, each read whole or
/// not at all, neither writable, nothing past them addressable. Both hold
/// typed kernel pointers this verifier proves no field access through, so a
/// program may observe a slot and may never follow it.
/// # C: O(1)
fn iter_access(offset: usize, size: usize, write: bool) -> bool {
    let slot = crate::bpf::ITER_SLOT_BYTES;
    !write && size == slot && offset % slot == 0 && offset < iter_context_bytes()
}

/// Covers `[start, start + size)` entirely within `[from, to)`. # C: O(1)
fn within(offset: usize, size: usize, from: usize, to: usize) -> bool {
    offset >= from && offset.checked_add(size).is_some_and(|end| end <= to)
}

/// Whether `offset` starts inside the half-open field range. # C: O(1)
fn starts_in(offset: usize, from: usize, to: usize) -> bool { offset >= from && offset < to }

/// Socket-filter context contract. Fields a socket filter may never see are
/// refused first, writes are confined to the control block, and the
/// remaining accesses go through the shared skb field rules.
/// # C: O(1)
fn sk_filter_access(offset: usize, size: usize, write: bool) -> bool {
    let hidden = starts_in(offset, sk_buff::TC_CLASSID, sk_buff::DATA)
        || starts_in(offset, sk_buff::DATA, sk_buff::DATA_END)
        || starts_in(offset, sk_buff::DATA_END, sk_buff::NAPI_ID)
        || starts_in(offset, sk_buff::DATA_META, sk_buff::FLOW_KEYS)
        || starts_in(offset, sk_buff::FAMILY, sk_buff::LOCAL_PORT_END)
        || starts_in(offset, sk_buff::TSTAMP, sk_buff::WIRE_LEN)
        || starts_in(offset, sk_buff::WIRE_LEN, sk_buff::GSO_SEGS)
        || starts_in(offset, sk_buff::HWTSTAMP, sk_buff::SIZE);
    if hidden { return false; }
    if write && !starts_in(offset, sk_buff::CB, sk_buff::CB_END) { return false; }
    skb_field_access(offset, size, write) && modelled_sk_filter_field(offset, size)
}

/// `struct sk_reuseport_md` access contract. Nothing in this context is
/// writable, and the four members whose value is a kernel pointer — the two
/// packet bounds and the two socket handles — are refused outright: this
/// kernel publishes no pointer a selection program could follow, so serving
/// them as zeroes would let a program believe an empty packet and a socket
/// at address zero. A program reads the packet through `bpf_skb_load_bytes`
/// against `len`, which is the same route a socket filter takes.
/// # C: O(1)
fn sk_reuseport_access(offset: usize, size: usize, write: bool) -> bool {
    if write || size == 0 || !size.is_power_of_two() || offset % size != 0 { return false; }
    // The access lies wholly inside one published member. Width is bounded by
    // that alone: a member is one word, so a doubleword read of one is an
    // access running off its end.
    modelled_sk_reuseport_field(offset, size)
}

/// Members the reuseport context builder actually fills, each read whole or
/// as a power-of-two slice that stays inside it. # C: O(1)
fn modelled_sk_reuseport_field(offset: usize, size: usize) -> bool {
    use sk_reuseport_md as md;
    [md::LEN, md::ETH_PROTOCOL, md::IP_PROTOCOL, md::BIND_INANY, md::HASH]
        .into_iter()
        .any(|field| within(offset, size, field, field + md::WORD))
}

/// Field rules shared by every skb-context program type. # C: O(1)
fn skb_field_access(offset: usize, size: usize, write: bool) -> bool {
    if size == 0 || offset >= sk_buff::SIZE { return false; }
    if offset % size != 0 { return false; }
    if starts_in(offset, sk_buff::CB, sk_buff::CB_END) {
        return within(offset, size, sk_buff::CB, sk_buff::CB_END);
    }
    if starts_in(offset, sk_buff::DATA, sk_buff::NAPI_ID)
        || starts_in(offset, sk_buff::DATA_META, sk_buff::FLOW_KEYS) {
        return size == sk_buff::WORD;
    }
    if starts_in(offset, sk_buff::REMOTE_IP4, sk_buff::REMOTE_PORT) {
        return size == sk_buff::WORD;
    }
    if starts_in(offset, sk_buff::FLOW_KEYS, sk_buff::TSTAMP) { return false; }
    if starts_in(offset, sk_buff::HWTSTAMP, sk_buff::SIZE) {
        return !write && size == sk_buff::WIDE;
    }
    if starts_in(offset, sk_buff::TSTAMP, sk_buff::WIRE_LEN) { return size == sk_buff::WIDE; }
    if starts_in(offset, sk_buff::SK, sk_buff::GSO_SIZE) {
        return !write && size == sk_buff::WIDE;
    }
    if starts_in(offset, sk_buff::TSTAMP_TYPE, sk_buff::HWTSTAMP) { return false; }
    // Remaining word-wide fields: a write replaces the whole word, a read
    // may take any power-of-two slice of it.
    if write { size == sk_buff::WORD } else { size <= sk_buff::WORD && size.is_power_of_two() }
}

/// Fields the socket-filter context builder actually fills. A legal
/// `__sk_buff` field this kernel cannot source is refused at load, never
/// served as a zero.
/// # C: O(1)
fn modelled_sk_filter_field(offset: usize, size: usize) -> bool {
    within(offset, size, sk_buff::LEN, sk_buff::LEN + sk_buff::WORD)
        || within(offset, size, sk_buff::PROTOCOL, sk_buff::PROTOCOL + sk_buff::WORD)
        || within(offset, size, sk_buff::IFINDEX, sk_buff::IFINDEX + sk_buff::WORD)
        || within(offset, size, sk_buff::CB, sk_buff::CB_END)
}

/// `struct bpf_sock_addr` access contract for the bind and connect hooks.
/// # C: O(1)
fn sock_addr_access(
    expected_attach_type: u32,
    offset: usize,
    size: usize,
    write: bool,
) -> bool {
    use uapi::attach_type as a;
    if size == 0 || offset % size != 0 { return false; }
    let inet4 = matches!(expected_attach_type, a::CGROUP_INET4_BIND | a::CGROUP_INET4_CONNECT);
    let inet6 = matches!(expected_attach_type, a::CGROUP_INET6_BIND | a::CGROUP_INET6_CONNECT);
    if write {
        return size == 4 && offset == 24
            || inet4 && size == 4 && offset == 4
            || inet6 && matches!(size, 4 | 8) && within(offset, size, 8, 24);
    }
    size == 4 && matches!(offset, 0 | 28 | 32 | 36)
        || matches!(size, 1 | 2 | 4) && within(offset, size, 24, 28)
        || inet4 && matches!(size, 1 | 2 | 4) && within(offset, size, 4, 8)
        || inet6 && matches!(size, 1 | 2 | 4 | 8) && within(offset, size, 8, 24)
}
