//! User boundary for the RTL CRC-32 accumulation: copy the caller's byte run
//! in bounded chunks and fold it onto the residue it supplied.

use alloc::vec;
use syscall::nt::{NtCall, NtService};

use super::checksum::accumulate;

/// Bytes one accumulation copies out of user memory at a time.
const CHUNK_BYTES: usize = 4096;

/// Route the RTL CRC-32 accumulation. The export returns the new residue and
/// carries no status channel, so a null run answers with the residue itself.
/// # C: O(N_bytes) plus the bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlComputeCrc32 { return None; }
    Some(compute(call.args.a0 as u32, call.args.a1, call.args.a2 as u32) as u64)
}

fn compute(residue: u32, data: u64, length: u32) -> u32 {
    if data == 0 { return 0; }
    let mut value = residue;
    let mut offset = 0u32;
    while offset < length {
        let span = CHUNK_BYTES.min((length - offset) as usize);
        let mut chunk = vec![0u8; span];
        let Some(slot) = data.checked_add(offset as u64) else { return value; };
        if uaccess::copy_from_user(&mut chunk, slot).is_err() { return value; }
        value = accumulate(value, &chunk);
        offset += span as u32;
    }
    value
}
