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

/// Bytes of context this kernel publishes for a socket filter. The whole
/// `struct __sk_buff` is materialised so that field admission is decided by
/// the field rules below rather than by where a buffer happens to stop;
/// every field those rules refuse is unreachable, so its bytes are never
/// observable.
pub const SK_FILTER_CONTEXT_BYTES: usize = sk_buff::SIZE;

/// Context window a cgroup program's pointer arithmetic may address.
const CGROUP_CONTEXT_BYTES: usize = 64;

/// Bytes of context an iterator program addresses: the iteration meta
/// record and the object of the current step. Every published target
/// declares the same two, so the shape belongs to the program type.
use crate::bpf::iter_context_bytes;

/// Upper bound on context-relative addressing for one program.
/// # C: O(1)
pub(super) fn context_size(profile: &Profile) -> usize {
    match (profile.prog_type, profile.hook) {
        (uapi::prog_type::SOCKET_FILTER, _) => SK_FILTER_CONTEXT_BYTES,
        (uapi::prog_type::LSM, Some(hook)) => bpf_lsm::context_bytes(hook),
        (uapi::prog_type::TRACING, _) => iter_context_bytes(),
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
        uapi::prog_type::CGROUP_SKB =>
            !write && size == sk_buff::WORD
                && matches!(offset, sk_buff::LEN | sk_buff::PROTOCOL | sk_buff::IFINDEX),
        uapi::prog_type::CGROUP_SOCK_ADDR =>
            sock_addr_access(profile.expected_attach_type, offset, size, write),
        uapi::prog_type::LSM =>
            profile.hook.is_some_and(|hook| lsm_access(hook, offset, size, write)),
        uapi::prog_type::TRACING => iter_access(offset, size, write),
        _ => false,
    }
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
