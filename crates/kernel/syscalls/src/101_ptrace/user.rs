// The USER-BUFFER half of ptrace: every layout, length rule and chunking plan
// that the copy-in/copy-out paths in the kernel-gated siblings
// (`info.rs`, `mem.rs`, `regset.rs`, `sig.rs`) need before they touch a user
// address.
//
// Ungated on purpose (`docs/53`): those four files carry a whole-file
// `#[cfg(target_os = "oxide-kernel")]`, so a test written beside them compiles
// to nothing and reports ok. Bytes in / bytes out lives here, where
// `cargo test` reaches it; the siblings keep only the `uaccess` call and the
// errno propagation.

use syscall::errno::Errno;
use crate::s101_ptrace_uapi as uapi;

/// One register word of a regset transfer.
pub const WORD: usize = 8;

/// `struct iovec` — the buffer PTRACE_GETREGSET/SETREGSET actually name.
pub const IOVEC_BYTES: usize = 16;

/// `{iov_base, iov_len}`, read as the reference does with two `__get_user`s on
/// an unaligned-tolerant pointer pair.
/// # C: O(1)
pub fn parse_iovec(rec: &[u8; IOVEC_BYTES]) -> (u64, u64) {
    (u64_at(rec, 0), u64_at(rec, 8))
}

/// How many bytes a copy-out may write: the record's own size, clamped to the
/// buffer the tracer offered. The RETURN value stays the full size — that is
/// how a tracer learns it must grow its buffer.
/// # C: O(1)
pub fn copy_len(actual: usize, user_size: u64) -> usize {
    if (actual as u64) < user_size { actual } else { user_size as usize }
}

/// Number of 8-byte chunks a byte-granular regset transfer of `n` bytes needs.
/// A trailing partial word counts: `copy_regset_to_user` is byte-granular, so
/// an `iov_len` that is not a multiple of 8 transfers its remainder rather than
/// dropping it.
/// # C: O(1)
pub fn nr_chunks(n: usize) -> usize { (n + WORD - 1) / WORD }

/// Length of chunk `i` of an `n`-byte transfer — 8 for every chunk but a
/// trailing partial one.
/// # C: O(1)
pub fn chunk_len(n: usize, i: usize) -> usize {
    let done = i * WORD;
    if done >= n { 0 } else if n - done < WORD { n - done } else { WORD }
}

/// Overlay the first `new.len()` bytes of `word` with `new`, leaving the tail
/// at its current value. This is `copy_regset_from_user`'s partial-write rule
/// at word granularity: a short `iov_len` must not zero the bytes it did not
/// carry.
/// # C: O(1)
pub fn merge_tail(word: u64, new: &[u8]) -> u64 {
    let mut b = word.to_ne_bytes();
    b[..new.len()].copy_from_slice(new);
    u64::from_ne_bytes(b)
}

/// NT_PRSTATUS copy-OUT, byte-granular: hand each 8-byte chunk (the last one
/// possibly short) to `put` at its offset from the iovec base. Transferring in
/// chunks rather than through one struct-sized buffer keeps the aarch64
/// syscall chain — whose 272-byte regset would otherwise be on the stack twice
/// — inside its budget.
/// # C: O(n / 8)
pub fn regs_out<F>(regs: &[u64], n: usize, mut put: F) -> Result<(), Errno>
    where F: FnMut(usize, &[u8]) -> Result<(), Errno>
{
    for i in 0..nr_chunks(n) {
        let b = regs[i].to_ne_bytes();
        put(i * WORD, &b[..chunk_len(n, i)])?;
    }
    Ok(())
}

/// NT_PRSTATUS copy-IN, byte-granular, with `copy_regset_from_user`'s
/// partial-write rule: bytes the tracer did not supply keep their current
/// value, including inside a trailing partial word.
/// # C: O(n / 8)
pub fn regs_in<F>(regs: &mut [u64], n: usize, mut get: F) -> Result<(), Errno>
    where F: FnMut(usize, &mut [u8]) -> Result<(), Errno>
{
    for i in 0..nr_chunks(n) {
        let len = chunk_len(n, i);
        let mut b = [0u8; WORD];
        get(i * WORD, &mut b[..len])?;
        regs[i] = merge_tail(regs[i], &b[..len]);
    }
    Ok(())
}

/// `struct sock_filter` wire bytes — code@0, jt@2, jf@3, k@4.
/// # C: O(1)
pub fn sock_filter_bytes(code: u16, jt: u8, jf: u8, k: u32) -> [u8; uapi::SOCK_FILTER_BYTES] {
    let mut b = [0u8; uapi::SOCK_FILTER_BYTES];
    b[0..2].copy_from_slice(&code.to_ne_bytes());
    b[2] = jt;
    b[3] = jf;
    b[4..8].copy_from_slice(&k.to_ne_bytes());
    b
}

/// PTRACE_SECCOMP_GET_METADATA's size rule: the record is clamped to its own
/// size, and a buffer too small to carry back `filter_off` is EINVAL rather
/// than a short write.
/// # C: O(1)
pub fn metadata_size(size: u64) -> Result<usize, Errno> {
    let size = if size as usize > uapi::SECCOMP_METADATA_BYTES {
        uapi::SECCOMP_METADATA_BYTES
    } else { size as usize };
    if size < FILTER_OFF_BYTES { return Err(Errno::Einval); }
    Ok(size)
}

/// `sizeof(struct seccomp_metadata.filter_off)`.
pub const FILTER_OFF_BYTES: usize = 8;

/// `struct seccomp_metadata` — filter_off@0, flags@8.
/// # C: O(1)
pub fn metadata_rec(filter_off: u64, flags: u64) -> [u8; uapi::SECCOMP_METADATA_BYTES] {
    let mut b = [0u8; uapi::SECCOMP_METADATA_BYTES];
    b[0..8].copy_from_slice(&filter_off.to_ne_bytes());
    b[8..16].copy_from_slice(&flags.to_ne_bytes());
    b
}

/// `struct ptrace_rseq_configuration` — rseq_abi_pointer@0, rseq_abi_size@8,
/// signature@12, flags@16, pad@20.
/// # C: O(1)
pub fn rseq_rec(ptr: u64, len: u32, sig: u32) -> [u8; uapi::RSEQ_CONFIGURATION_BYTES] {
    let mut b = [0u8; uapi::RSEQ_CONFIGURATION_BYTES];
    b[0..8].copy_from_slice(&ptr.to_ne_bytes());
    b[8..12].copy_from_slice(&len.to_ne_bytes());
    b[12..16].copy_from_slice(&sig.to_ne_bytes());
    b
}

/// `struct ptrace_peeksiginfo_args` — off@0, flags@8, nr@12.
/// # C: O(1)
pub fn parse_peeksiginfo_args(rec: &[u8; 16]) -> (u64, u32, i32) {
    (u64_at(rec, 0), u32_at(rec, 8), u32_at(rec, 12) as i32)
}

/// The two `siginfo_t` fields PTRACE_SETSIGINFO reads before it hands the
/// record to the shared classifier: si_signo@0 and si_code@8. The 48-byte
/// kernel prefix is followed by an expansion area this kernel cannot retain,
/// so the caller tests bytes 48.. for zero.
/// # C: O(1)
pub fn siginfo_prefix(rec: &[u8; SIGINFO_BYTES]) -> (u32, i32) {
    (u32_at(rec, 0), u32_at(rec, 8) as i32)
}

/// `sizeof(siginfo_t)` as the ABI presents it to a tracer.
pub const SIGINFO_BYTES: usize = uapi::SIGINFO_BYTES as usize;

/// First byte of the expansion area a future layout could use.
pub const SIGINFO_KERNEL_PREFIX: usize = 48;

fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[off..off + 8]);
    u64::from_ne_bytes(w)
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    let mut w = [0u8; 4];
    w.copy_from_slice(&b[off..off + 4]);
    u32::from_ne_bytes(w)
}

#[cfg(test)]
#[path = "user/tests.rs"] mod tests;
