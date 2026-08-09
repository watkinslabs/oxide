// Running a ring's BPF filters against one submission.
//
// The enforcement point is submission admission, beside the restriction
// allow-list: a denied request never runs, and reports `EACCES` exactly as a
// request refused by a restriction does. Putting it anywhere later would let a
// filtered opcode take its side effect before the filter was consulted.
//
// The per-opcode payload is read from the SQE here rather than from a prepared
// request, because oxide prepares and issues in one step. Two opcodes need the
// caller's memory to describe themselves — an `openat2` reads its `open_how`
// and a `connect` its address — and a copy that faults simply leaves the
// payload zero: the request is about to fail on the same pointer, and a filter
// must not be handed a half-read record.

use alloc::sync::Arc;

use syscall::errno::Errno;

use security::seccomp::interp::run_filter_bytes;

use crate::io_uring_abi::bpf_filter::{build_ctx, filter_allows, Pdu, Verdict};
use crate::io_uring_abi::ops::*;
use crate::io_uring_sqe::Sqe;

use super::ctx::IoUringInode;

/// `sizeof(struct open_how)` — {flags u64, mode u64, resolve u64}.
const OPEN_HOW_BYTES: usize = 24;
/// Bytes of a `sockaddr` that must be present before its family means
/// anything.
const SA_FAMILY_BYTES: u64 = 2;
/// `AF_INET` / `AF_INET6`, and the offsets of the port and address inside the
/// two address forms a filter can inspect.
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const SIN_PORT_OFF: u64 = 2;
const SIN_ADDR_OFF: u64 = 4;
const SIN_BYTES: u64 = 16;
const SIN6_ADDR_OFF: u64 = 8;
const SIN6_BYTES: u64 = 28;

/// Read `N` bytes of user memory, or `None`. # C: O(N)
fn read<const N: usize>(at: u64) -> Option<[u8; N]> {
    let mut b = [0u8; N];
    if uaccess::copy_from_user(&mut b, at).is_err() { return None; }
    Some(b)
}

/// The payload a filter for this opcode sees. # C: O(1)
fn pdu_of(sqe: &Sqe) -> Pdu {
    match sqe.opcode {
        IORING_OP_SOCKET => Pdu::Socket {
            family: sqe.fd as u32, ty: sqe.off as u32, protocol: sqe.len,
        },
        // `openat` builds its `open_how` from the SQE's own words, and never
        // resolves under a `RESOLVE_*` mask.
        IORING_OP_OPENAT => Pdu::Open {
            flags: sqe.op_flags as u64, mode: sqe.len as u64, resolve: 0,
        },
        IORING_OP_OPENAT2 => {
            if sqe.len as usize != OPEN_HOW_BYTES { return Pdu::Open { flags: 0, mode: 0, resolve: 0 }; }
            let Some(b) = read::<OPEN_HOW_BYTES>(sqe.off) else {
                return Pdu::Open { flags: 0, mode: 0, resolve: 0 };
            };
            let g = |o: usize| { let mut v = [0u8; 8]; v.copy_from_slice(&b[o..o + 8]); u64::from_le_bytes(v) };
            Pdu::Open { flags: g(0), mode: g(8), resolve: g(16) }
        }
        IORING_OP_CONNECT => connect_pdu(sqe),
        _ => Pdu::None,
    }
}

/// A connect's address, as far as the caller's own `addr_len` covers it.
///
/// Fields the length does not reach stay zero rather than being read anyway —
/// the reference is explicit that a short address must not let stale bytes
/// reach a filter, because a filter comparing a port it was never given would
/// make an allow decision on noise. # C: O(1)
fn connect_pdu(sqe: &Sqe) -> Pdu {
    let none = Pdu::Connect { family: 0, port: 0, addr: [0; 16] };
    let addr_len = sqe.off;
    if addr_len < SA_FAMILY_BYTES { return none; }
    let Some(fb) = read::<2>(sqe.addr) else { return none };
    let family = u16::from_ne_bytes(fb) as u32;
    let mut port = 0u16;
    let mut addr = [0u8; 16];
    match family {
        AF_INET if addr_len >= SIN_BYTES => {
            if let Some(p) = read::<2>(sqe.addr + SIN_PORT_OFF) { port = u16::from_be_bytes(p); }
            if let Some(a) = read::<4>(sqe.addr + SIN_ADDR_OFF) { addr[0..4].copy_from_slice(&a); }
        }
        AF_INET6 if addr_len >= SIN6_BYTES => {
            if let Some(p) = read::<2>(sqe.addr + SIN_PORT_OFF) { port = u16::from_be_bytes(p); }
            if let Some(a) = read::<16>(sqe.addr + SIN6_ADDR_OFF) { addr.copy_from_slice(&a); }
        }
        _ => {}
    }
    Pdu::Connect { family, port, addr }
}

/// Admit one submission against the ring's filters.
///
/// Fails closed at every step: a denied opcode, a program returning zero, and
/// a program that could not run at all are all `EACCES`. # C: O(F x I)
pub fn admit(inode: &Arc<IoUringInode>, sqe: &Sqe) -> Result<(), Errno> {
    // The common case is a ring with no filters, and it must cost one load —
    // not a record build and not a table walk.
    let progs = {
        let g = inode.reg.lock();
        if !g.bpf.active() { return Ok(()); }
        match g.bpf.verdict(sqe.opcode) {
            Verdict::Allow => return Ok(()),
            Verdict::Deny => return Err(Errno::Eacces),
            // Cloned out of the lock: a program runs for as long as its own
            // instruction count, which is not the work of a spinlock section,
            // and the set can be registered into from another task meanwhile.
            Verdict::Run(p) => p.to_vec(),
        }
    };
    let ctx = build_ctx(sqe.opcode, sqe.flags, sqe.user_data, &pdu_of(sqe));
    for prog in progs.iter() {
        if !filter_allows(run_filter_bytes(prog, &ctx)) { return Err(Errno::Eacces); }
    }
    Ok(())
}
