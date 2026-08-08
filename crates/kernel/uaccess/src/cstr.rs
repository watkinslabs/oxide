// `strncpy_from_user` — the NUL-terminated user-string read.
//
// WHY THIS LIVES HERE AND NOT BESIDE THE POINTER TYPES
//
// A range check answers "is this address in the user half". It does NOT answer
// "will loading from it fault". The two are only interchangeable when the
// faulting instruction carries an exception-table fixup, so a fault at it
// resumes at a recovery label and reports how much was left instead of killing
// the kernel. `crates/arch/hal-{x86_64,aarch64}/src/uaccess.rs` provide exactly
// that: hand-written copy loops whose load and store are registered in
// `__ex_table`, recovered by the fault dispatcher.
//
// A compiler-generated `read_volatile` on a user address has NO such entry.
// Range-checking one and then reading it raw is a kernel-mode fault waiting for
// an address that is merely inside the user half and mapped by nothing — which
// is any pointer a program is free to pass. That shape killed a boot on both
// arches from a syscall argument.
//
// So the scan copies through `raw_copy_from_user` and treats a short copy as
// the fault it is. The policy — how far to walk, which errno each stopping
// condition earns — is `scan_cstr`, which takes the copy as a parameter and is
// therefore drivable, and breakable, from a hosted test with no user memory and
// no target.

use alloc::vec::Vec;

use hal::{PAGE_SIZE_BYTES, USER_VA_END};
use syscall::errno::Errno;

use crate::copy::raw_copy_from_user;

/// `strncpy_from_user`: copy a NUL-terminated C string out of the current
/// address space starting at `base`, into an owned `Vec` (NUL excluded).
///
///   * first `0` byte inside `count` → `Ok(bytes_before_nul)`;
///   * `count` bytes with no NUL → `Ok(count bytes)`, the caller's own bound
///     reached and reported by the LENGTH of the result, not by an error;
///   * a read that faults, or a walk that reaches `USER_VA_END` with bytes of
///     `count` still owed → `Efault`.
///
/// `base == 0` is `Efault`: the range check inside the copy rejects a null
/// pointer with a non-zero length, so no caller has to test for it first.
/// # C: O(count)
pub fn strncpy_from_user(base: u64, count: u64) -> Result<Vec<u8>, Errno> {
    scan_cstr(base, count, |dst, src| {
        // SAFETY: `raw_copy_from_user` range-checks `src` itself and recovers a user fault through the exception table; `dst` is a live kernel-owned slice writable for its whole length.
        unsafe { raw_copy_from_user(dst.as_mut_ptr(), src, dst.len()) }
    })
}

/// `strndup_user`: [`strncpy_from_user`] plus the length VERDICT its callers
/// share — a string that fills `n` without terminating is `Enametoolong`, never
/// a silent `n`-byte prefix that resolves to something else. Kept separate
/// because the truncating form is the one a caller applying its own over-long
/// rule needs, and collapsing the two would force one of them to lie.
/// # C: O(n)
pub fn strndup_user(base: u64, n: u64) -> Result<Vec<u8>, Errno> {
    strndup_verdict(strncpy_from_user(base, n)?, n)
}

/// The verdict itself, over an already-read string, so it is drivable from a
/// hosted test against a fake address space rather than only through real user
/// memory. A result that reached the caller's own bound did not terminate.
/// # C: O(1)
pub fn strndup_verdict(b: Vec<u8>, n: u64) -> Result<Vec<u8>, Errno> {
    if b.len() as u64 >= n { return Err(Errno::Enametoolong); }
    Ok(b)
}

/// The scan policy, over a copy primitive that reports how many bytes it could
/// NOT transfer — the same contract `raw_copy_from_user` has, so a fault is
/// distinguishable from a short but complete read.
///
/// Reads advance one page at a time and never straddle `USER_VA_END`. Page
/// granularity is not an optimisation detail: it keeps the scan from touching a
/// page the string does not reach into, and it bounds how much a single
/// recovered fault has to unwind.
/// # C: O(count)
pub fn scan_cstr(
    base: u64,
    count: u64,
    mut copy: impl FnMut(&mut [u8], u64) -> usize,
) -> Result<Vec<u8>, Errno> {
    if base >= USER_VA_END { return Err(Errno::Efault); }
    let mut out: Vec<u8> = Vec::new();
    let mut done: u64 = 0;
    while done < count {
        let cur = base.checked_add(done).ok_or(Errno::Efault)?;
        if cur >= USER_VA_END { return Err(Errno::Efault); }
        let to_page_end = PAGE_SIZE_BYTES - (cur & (PAGE_SIZE_BYTES - 1));
        let chunk = (count - done).min(to_page_end).min(USER_VA_END - cur) as usize;
        let at = out.len();
        out.resize(at + chunk, 0);
        let left = copy(&mut out[at..], cur);
        let got = chunk.saturating_sub(left);
        if let Some(i) = out[at..at + got].iter().position(|&b| b == 0) {
            out.truncate(at + i);
            return Ok(out);
        }
        // Nothing terminated the string inside what was readable, so the byte
        // that stopped the copy is the answer: a short copy is a fault.
        if left != 0 { return Err(Errno::Efault); }
        done += chunk as u64;
    }
    Ok(out)
}

#[cfg(test)] mod tests;
