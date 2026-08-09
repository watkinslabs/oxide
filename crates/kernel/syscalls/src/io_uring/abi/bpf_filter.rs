// `IORING_REGISTER_BPF_FILTER` — per-opcode classic-BPF filters on a ring's
// submissions.
//
// A filter is a classic BPF program over a fixed kernel-supplied record
// describing the request about to run: its opcode, its SQE flags, its
// `user_data`, and — for the opcodes that carry one — a small per-opcode
// payload (the socket's family/type/protocol, an open's flags/mode/resolve, a
// connect's address family/port/address). The program returns non-zero to
// allow the request and zero to deny it, and a denied request is `EACCES`.
//
// This is the SAME instruction set, the same load-time verifier and the same
// interpreter seccomp uses (`security::seccomp::{verifier, interp}`), with the
// context length as the only difference. A second cBPF implementation here
// could disagree with that one about what a program means, which is precisely
// the class of split the sandbox cannot survive: the two would accept
// different programs and a filter verified by one could read past the record
// sized by the other.
//
// Filters STACK per opcode: registering a second filter for an opcode does not
// replace the first, and an opcode is allowed only if every filter registered
// for it allows it. `IO_URING_BPF_FILTER_DENY_REST` additionally plants a deny
// marker on every opcode that has no filter yet, which is what turns a filter
// set from an allow-list of exceptions into a default-deny policy.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use super::ops::OP_LAST;

/// `sizeof(struct io_uring_bpf_filter)`.
pub const BPF_FILTER_BYTES: u64 = 64;
/// Byte offset of the filter sub-struct inside `struct io_uring_bpf`.
pub const BPF_FILTER_OFF: u64 = 8;
/// `sizeof(struct io_uring_bpf)` — an 8-byte header and the filter union.
pub const IOU_BPF_BYTES: u64 = BPF_FILTER_OFF + BPF_FILTER_BYTES;

/// `IO_URING_BPF_CMD_FILTER` — the only command this registration carries.
pub const IO_URING_BPF_CMD_FILTER: u16 = 1;

/// `IO_URING_BPF_FILTER_DENY_REST` — plant a deny marker on every opcode that
/// has no filter yet.
pub const IO_URING_BPF_FILTER_DENY_REST: u32 = 1;
/// `IO_URING_BPF_FILTER_SZ_STRICT` — refuse the registration when the caller
/// and this kernel disagree about the opcode's payload size, instead of
/// accepting the caller's smaller view of it.
pub const IO_URING_BPF_FILTER_SZ_STRICT: u32 = 2;
/// Every defined filter flag.
pub const IO_URING_BPF_FILTER_FLAGS: u32 =
    IO_URING_BPF_FILTER_DENY_REST | IO_URING_BPF_FILTER_SZ_STRICT;

/// `BPF_MAXINSNS` — longest classic program the loader accepts.
pub const BPF_MAXINSNS: u32 = 4096;
/// `sizeof(struct sock_filter)`.
pub const SOCK_FILTER_BYTES: u64 = 8;

// --- the record a filter reads ------------------------------------------

/// `sizeof(struct io_uring_bpf_ctx)`. This is what bounds every
/// `BPF_LD|BPF_W|BPF_ABS` a filter may issue.
pub const BPF_CTX_BYTES: u32 = 40;
/// Offset of `user_data`.
pub const CTX_USER_DATA: usize = 0;
/// Offset of `opcode`.
pub const CTX_OPCODE: usize = 8;
/// Offset of `sqe_flags`.
pub const CTX_SQE_FLAGS: usize = 9;
/// Offset of `pdu_size` — and of the region the reference clears before each
/// run, so no residue of an earlier request is ever visible to a filter.
pub const CTX_PDU_SIZE: usize = 10;
/// Offset of the per-opcode payload union.
pub const CTX_PDU: usize = 16;

/// Payload size for `IORING_OP_SOCKET` — {family, type, protocol}.
pub const PDU_SOCKET: u8 = 12;
/// Payload size for the open opcodes — {flags, mode, resolve}.
pub const PDU_OPEN: u8 = 24;
/// Payload size for `IORING_OP_CONNECT` — {family, port, pad, address}.
pub const PDU_CONNECT: u8 = 24;

/// The payload size THIS kernel supplies for an opcode. Zero means the opcode
/// carries no payload and a filter sees only the header. # C: O(1)
pub fn pdu_size_for(opcode: u32) -> u8 {
    use super::ops::*;
    match opcode as u8 {
        IORING_OP_SOCKET => PDU_SOCKET,
        IORING_OP_OPENAT | IORING_OP_OPENAT2 => PDU_OPEN,
        IORING_OP_CONNECT => PDU_CONNECT,
        _ => 0,
    }
}

/// The per-opcode payload a filter sees. Absent for every opcode whose
/// [`pdu_size_for`] is zero, which is most of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pdu {
    None,
    Socket { family: u32, ty: u32, protocol: u32 },
    Open { flags: u64, mode: u64, resolve: u64 },
    /// `port` and `addr` are in NETWORK byte order, as the caller supplied
    /// them: a filter compares them against constants it built the same way.
    Connect { family: u32, port: u16, addr: [u8; 16] },
}

/// Build the record a filter runs against.
///
/// Everything from `pdu_size` onward is written from scratch each time — the
/// reference clears that whole tail before populating it, so a filter for an
/// opcode with a small payload can never read the remains of a larger one.
/// # C: O(1)
pub fn build_ctx(opcode: u8, sqe_flags: u8, user_data: u64, pdu: &Pdu) -> [u8; BPF_CTX_BYTES as usize] {
    let mut b = [0u8; BPF_CTX_BYTES as usize];
    b[CTX_USER_DATA..CTX_USER_DATA + 8].copy_from_slice(&user_data.to_ne_bytes());
    b[CTX_OPCODE] = opcode;
    b[CTX_SQE_FLAGS] = sqe_flags;
    b[CTX_PDU_SIZE] = pdu_size_for(opcode as u32);
    match *pdu {
        Pdu::None => {}
        Pdu::Socket { family, ty, protocol } => {
            b[CTX_PDU..CTX_PDU + 4].copy_from_slice(&family.to_ne_bytes());
            b[CTX_PDU + 4..CTX_PDU + 8].copy_from_slice(&ty.to_ne_bytes());
            b[CTX_PDU + 8..CTX_PDU + 12].copy_from_slice(&protocol.to_ne_bytes());
        }
        Pdu::Open { flags, mode, resolve } => {
            b[CTX_PDU..CTX_PDU + 8].copy_from_slice(&flags.to_ne_bytes());
            b[CTX_PDU + 8..CTX_PDU + 16].copy_from_slice(&mode.to_ne_bytes());
            b[CTX_PDU + 16..CTX_PDU + 24].copy_from_slice(&resolve.to_ne_bytes());
        }
        Pdu::Connect { family, port, addr } => {
            b[CTX_PDU..CTX_PDU + 4].copy_from_slice(&family.to_ne_bytes());
            // Network byte order on the wire, so the two bytes go out as they
            // arrived rather than through a host-order conversion.
            b[CTX_PDU + 4..CTX_PDU + 6].copy_from_slice(&port.to_be_bytes());
            b[CTX_PDU + 8..CTX_PDU + 24].copy_from_slice(&addr);
        }
    }
    b
}

// --- the registration record --------------------------------------------

/// `struct io_uring_bpf` flattened: the header plus its one union member.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct IouBpf {
    pub cmd_type: u16,
    pub cmd_flags: u16,
    pub resv: u32,
    pub opcode: u32,
    pub flags: u32,
    pub filter_len: u32,
    pub pdu_size: u8,
    pub f_resv: [u8; 3],
    pub filter_ptr: u64,
    pub f_resv2: [u64; 5],
}

impl IouBpf {
    /// # C: O(1)
    pub fn from_bytes(b: &[u8; IOU_BPF_BYTES as usize]) -> Self {
        let g32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let g64 = |o: usize| { let mut v = [0u8; 8]; v.copy_from_slice(&b[o..o + 8]); u64::from_le_bytes(v) };
        let f = BPF_FILTER_OFF as usize;
        Self {
            cmd_type: u16::from_le_bytes([b[0], b[1]]),
            cmd_flags: u16::from_le_bytes([b[2], b[3]]),
            resv: g32(4),
            opcode: g32(f), flags: g32(f + 4), filter_len: g32(f + 8),
            pdu_size: b[f + 12], f_resv: [b[f + 13], b[f + 14], b[f + 15]],
            filter_ptr: g64(f + 16),
            f_resv2: [g64(f + 24), g64(f + 32), g64(f + 40), g64(f + 48), g64(f + 56)],
        }
    }

    /// The filter sub-struct's wire image, for the `pdu_size` write-back. Only
    /// the sub-struct is copied back — the header is the caller's and this
    /// call has no business rewriting it. # C: O(1)
    pub fn filter_bytes(&self) -> [u8; BPF_FILTER_BYTES as usize] {
        let mut b = [0u8; BPF_FILTER_BYTES as usize];
        b[0..4].copy_from_slice(&self.opcode.to_le_bytes());
        b[4..8].copy_from_slice(&self.flags.to_le_bytes());
        b[8..12].copy_from_slice(&self.filter_len.to_le_bytes());
        b[12] = self.pdu_size;
        b[13..16].copy_from_slice(&self.f_resv);
        b[16..24].copy_from_slice(&self.filter_ptr.to_le_bytes());
        for i in 0..5 { b[24 + i * 8..32 + i * 8].copy_from_slice(&self.f_resv2[i].to_le_bytes()); }
        b
    }

    /// Whether this registration also plants deny markers. # C: O(1)
    pub fn deny_rest(&self) -> bool { self.flags & IO_URING_BPF_FILTER_DENY_REST != 0 }
}

/// The structural half of the import ladder — everything decided before the
/// payload sizes are compared. # C: O(1)
pub fn admit_bpf_reg(r: &IouBpf) -> Result<(), Errno> {
    if r.cmd_type != IO_URING_BPF_CMD_FILTER { return Err(Errno::Einval); }
    if r.cmd_flags != 0 || r.resv != 0 { return Err(Errno::Einval); }
    if r.opcode >= OP_LAST as u32 { return Err(Errno::Einval); }
    if r.flags & !IO_URING_BPF_FILTER_FLAGS != 0 { return Err(Errno::Einval); }
    if r.f_resv != [0; 3] { return Err(Errno::Einval); }
    if r.f_resv2 != [0; 5] { return Err(Errno::Einval); }
    if r.filter_len == 0 || r.filter_len > BPF_MAXINSNS { return Err(Errno::Einval); }
    Ok(())
}

/// The payload-size negotiation.
///
/// A caller that agrees with this kernel is fine. A caller that disagrees is
/// refused under `SZ_STRICT`, and is also refused when it expects a LARGER
/// payload than this kernel supplies — it would be reading fields that are not
/// there. A caller expecting a smaller payload is accepted: its filter simply
/// ignores the tail.
///
/// Either way the caller is told the real size, which is why the reference
/// writes the record back even on the refusal. # C: O(1)
pub fn admit_pdu_size(caller: u8, kernel: u8, flags: u32) -> Result<(), Errno> {
    if caller == kernel { return Ok(()); }
    if flags & IO_URING_BPF_FILTER_SZ_STRICT != 0 { return Err(Errno::Emsgsize); }
    if caller > kernel { return Err(Errno::Emsgsize); }
    Ok(())
}

// --- the installed set ---------------------------------------------------

/// One opcode's filters. `deny` is the marker `DENY_REST` plants: it can only
/// land on an opcode that had no filter, and once present nothing the opcode
/// can do gets past it.
#[derive(Clone, Default)]
pub struct OpFilter {
    pub progs: Vec<Arc<Vec<u64>>>,
    pub deny: bool,
}

/// What a ring's filter set says about one opcode.
pub enum Verdict<'a> {
    /// No filter registered for this opcode.
    Allow,
    /// A deny marker is in this opcode's chain; nothing needs to run.
    Deny,
    /// Run these, newest first. Any program returning zero denies.
    Run(&'a [Arc<Vec<u64>>]),
}

/// A ring's (or a task's) filter set.
#[derive(Clone, Default)]
pub struct FilterSet {
    per_op: Vec<OpFilter>,
    /// Whether anything has been registered at all — the fast test the
    /// submission path makes before it builds a record.
    any: bool,
}

impl FilterSet {
    /// # C: O(1)
    pub fn new() -> Self { Self { per_op: Vec::new(), any: false } }

    /// Whether any filter is installed. # C: O(1)
    pub fn active(&self) -> bool { self.any }

    /// Grow to the full opcode table on first use. # C: O(OP_LAST)
    fn slots(&mut self) -> &mut Vec<OpFilter> {
        if self.per_op.is_empty() { self.per_op.resize(OP_LAST as usize, OpFilter::default()); }
        &mut self.per_op
    }

    /// Install `prog` for `opcode`, in front of whatever is already there, and
    /// plant deny markers when the registration asked for them.
    /// # C: O(OP_LAST)
    pub fn install(&mut self, opcode: u32, prog: Arc<Vec<u64>>, deny_rest: bool) {
        let op = opcode as usize;
        let slots = self.slots();
        if op < slots.len() { slots[op].progs.insert(0, prog); }
        if deny_rest {
            for (i, s) in slots.iter_mut().enumerate() {
                if i == op { continue; }
                // Only an EMPTY slot gets a marker: an opcode the caller has
                // already reasoned about keeps the filters it was given.
                if s.progs.is_empty() && !s.deny { s.deny = true; }
            }
        }
        self.any = true;
    }

    /// What this set says about `opcode`. # C: O(1)
    pub fn verdict(&self, opcode: u8) -> Verdict<'_> {
        let Some(s) = self.per_op.get(opcode as usize) else { return Verdict::Allow };
        if s.deny { return Verdict::Deny; }
        if s.progs.is_empty() { return Verdict::Allow; }
        Verdict::Run(&s.progs)
    }
}

/// Fold one program's return into an admission answer: zero denies, anything
/// else allows, and a program that could not run at all denies.
///
/// Failing closed is the whole contract. A filter that reached a state its
/// verification was supposed to prevent tells us nothing about the request, and
/// "nothing" must not read as permission. # C: O(1)
pub fn filter_allows(ret: Option<u32>) -> bool { matches!(ret, Some(v) if v != 0) }

#[cfg(test)]
#[path = "bpf_filter/tests.rs"]
mod tests;
