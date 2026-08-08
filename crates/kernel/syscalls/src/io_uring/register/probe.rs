// Opcode probing and the feature query — the two ways a caller asks what this
// kernel can do before it relies on it.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::io_uring_abi::enter::IORING_ENTER_FLAGS;
use crate::io_uring_abi::layout::REPORTED_FEATURES;
use crate::io_uring_abi::ops::{op_supported, OP_LAST, SQE_VALID_FLAGS};
use crate::io_uring_abi::register_op::*;
use crate::io_uring_abi::uapi::IORING_SETUP_FLAGS;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `IORING_REGISTER_PROBE`: `arg` is a `struct io_uring_probe` followed by
/// `nr` op slots. The op count is CLAMPED rather than refused, so a caller
/// that asked for more slots than there are opcodes is not faulted for a
/// buffer it sized correctly. # C: O(nr)
pub fn probe(arg: u64, nr: u32) -> i64 {
    let ops = probe_ops(nr, OP_LAST as u32);
    let total = (PROBE_HDR_BYTES + ops as u64 * PROBE_OP_BYTES) as usize;
    // The caller's image is read first and must be all zero, so it cannot
    // smuggle pre-set fields past the probe.
    let mut img: Vec<u8> = Vec::new();
    if img.try_reserve_exact(total).is_err() { return err(Errno::Enomem); }
    img.resize(total, 0);
    if uaccess::copy_from_user(&mut img[..], arg).is_err() { return err(Errno::Efault); }
    if img.iter().any(|&b| b != 0) { return err(Errno::Einval); }

    img[0] = OP_LAST - 1;   // last_op
    img[1] = ops as u8;     // ops_len
    for i in 0..ops as usize {
        let at = PROBE_HDR_BYTES as usize + i * PROBE_OP_BYTES as usize;
        img[at] = i as u8;
        let flags = if op_supported(i as u8) { IO_URING_OP_SUPPORTED } else { 0 };
        img[at + 2..at + 4].copy_from_slice(&flags.to_ne_bytes());
    }
    if uaccess::copy_to_user(arg, &img[..]).is_err() { return err(Errno::Efault); }
    0
}

/// `sizeof(struct io_uring_query_hdr)`.
const QUERY_HDR_BYTES: usize = 40;
/// `sizeof(struct io_uring_query_opcode)`.
const QUERY_OPCODE_BYTES: usize = 48;
/// `sizeof(struct io_uring_query_scq)`.
const QUERY_SCQ_BYTES: usize = 16;
/// Largest answer any query op produces.
const QUERY_MAX_BYTES: usize = QUERY_OPCODE_BYTES;
/// `IO_URING_QUERY_OPCODES`.
const QUERY_OPCODES: u32 = 0;
/// `IO_URING_QUERY_ZCRX`.
const QUERY_ZCRX: u32 = 1;
/// `IO_URING_QUERY_SCQ`.
const QUERY_SCQ: u32 = 2;
/// `IO_URING_QUERY_ZCRX_NOTIF`.
const QUERY_ZCRX_NOTIF: u32 = 3;
/// One past the last query op.
const QUERY_MAX_OP: u32 = 4;
/// Chain length bound, so a cyclic list cannot spin forever.
const QUERY_MAX_ENTRIES: u32 = 1000;

/// Fill the answer for one query op. `Err` is the per-entry result the header
/// carries; the syscall itself still succeeds. # C: O(1)
fn answer(op: u32, out: &mut [u8; QUERY_MAX_BYTES]) -> Result<usize, Errno> {
    match op {
        QUERY_OPCODES => {
            out[0..4].copy_from_slice(&(OP_LAST as u32).to_le_bytes());
            out[4..8].copy_from_slice(&IORING_REGISTER_LAST.to_le_bytes());
            out[8..16].copy_from_slice(&(REPORTED_FEATURES as u64).to_le_bytes());
            out[16..24].copy_from_slice(&(IORING_SETUP_FLAGS as u64).to_le_bytes());
            out[24..32].copy_from_slice(&(IORING_ENTER_FLAGS as u64).to_le_bytes());
            out[32..40].copy_from_slice(&(SQE_VALID_FLAGS as u64).to_le_bytes());
            out[40..44].copy_from_slice(&QUERY_MAX_OP.to_le_bytes());
            Ok(QUERY_OPCODE_BYTES)
        }
        QUERY_SCQ => {
            use crate::io_uring_abi::layout::RING_CQES;
            out[0..8].copy_from_slice(&(RING_CQES as u64).to_le_bytes());
            out[8..16].copy_from_slice(&(RING_CQES as u64).to_le_bytes());
            Ok(QUERY_SCQ_BYTES)
        }
        // A query about a mechanism this kernel does not have answers in the
        // entry's own result field, which is how a caller learns that one
        // query is unavailable without the whole chain failing.
        QUERY_ZCRX | QUERY_ZCRX_NOTIF => Err(Errno::Eopnotsupp),
        _ => Err(Errno::Eopnotsupp),
    }
}

/// Handle one chain entry, returning the next header's address. # C: O(1)
fn one_entry(uhdr: u64) -> Result<u64, i64> {
    let mut hdr = [0u8; QUERY_HDR_BYTES];
    if uaccess::copy_from_user(&mut hdr, uhdr).is_err() { return Err(err(Errno::Efault)); }
    let next = u64::from_le_bytes(hdr[0..8].try_into().unwrap_or([0; 8]));
    let data = u64::from_le_bytes(hdr[8..16].try_into().unwrap_or([0; 8]));
    let op   = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
    let usize_in = u32::from_le_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]) as usize;
    let result = i32::from_le_bytes([hdr[24], hdr[25], hdr[26], hdr[27]]);
    let resv_zero = hdr[28..40].iter().all(|&b| b == 0);

    let mut out = [0u8; QUERY_MAX_BYTES];
    let res = if op >= QUERY_MAX_OP {
        Err(Errno::Eopnotsupp)
    } else if !resv_zero || result != 0 || usize_in == 0 {
        Err(Errno::Einval)
    } else {
        answer(op, &mut out)
    };

    let (code, len) = match res {
        Ok(n) => (0i32, core::cmp::min(usize_in, n)),
        Err(e) => (-(e.as_i32()), 0),
    };
    if len > 0 && uaccess::copy_to_user(data, &out[..len]).is_err() {
        return Err(err(Errno::Efault));
    }
    hdr[20..24].copy_from_slice(&(len as u32).to_le_bytes());
    hdr[24..28].copy_from_slice(&code.to_le_bytes());
    if uaccess::copy_to_user(uhdr, &hdr).is_err() { return Err(err(Errno::Efault)); }
    Ok(next)
}

/// `IORING_REGISTER_QUERY`: walk a caller-linked chain of query headers.
/// # C: O(N_entries)
pub fn query(arg: u64, nr_args: u32) -> i64 {
    if nr_args != 0 { return err(Errno::Einval); }
    let mut uhdr = arg;
    let mut n = 0;
    while uhdr != 0 {
        match one_entry(uhdr) { Ok(next) => uhdr = next, Err(e) => return e }
        n += 1;
        if n >= QUERY_MAX_ENTRIES { return err(Errno::Erange); }
    }
    0
}
