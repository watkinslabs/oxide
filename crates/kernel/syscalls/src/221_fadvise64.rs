// 221 fadvise64 — POSIX file access-pattern advice (docs/53 §0).
// Linux `mm/fadvise.c`: `ksys_fadvise64_64` resolves the fd, then
// `generic_fadvise` validates and acts.
//
// The four state hints are REAL state, not decoration: NORMAL/SEQUENTIAL/RANDOM
// move the per-open `f_ra.ra_pages` ceiling that `File::ra_ondemand` reads on
// every buffered read, so a program that declares a sequential scan gets a
// wider window and one that declares random access gets none. DONTNEED flushes
// then drops whole resident cache pages; WILLNEED populates them. NOREUSE only
// biases LRU activation in Linux, which is the one hint with no local effect.
//
// Admission ladder + advice set live in `crate::fadvise_policy` (hosted-tested);
// this file is the shim (docs/53).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::fadvise_policy::{POSIX_FADV_DONTNEED, POSIX_FADV_NORMAL, POSIX_FADV_RANDOM,
    POSIX_FADV_SEQUENTIAL, POSIX_FADV_WILLNEED, fadvise_check};

const PAGE: u64 = hal::PAGE_SIZE_BYTES;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Linux `generic_fadvise`'s inclusive `endbyte`: `offset + len`, with `len ==
/// 0` ("as much as possible") and the unsigned wrap both collapsing to
/// `LLONG_MAX`. # C: O(1)
fn endbyte_of(offset: i64, len: i64) -> i64 {
    let end = (offset as u64).wrapping_add(len as u64);
    if len == 0 || end < len as u64 { i64::MAX } else { (end - 1) as i64 }
}

/// `sys_fadvise64(fd, offset, len, advice)` — slot 221.
/// Errors: EBADF (fd), ESPIPE (fd is a FIFO), EINVAL (negative offset/len, or
/// an advice value outside the POSIX six).
/// # C: O(pages in range) for WILLNEED/DONTNEED, O(1) otherwise
pub fn sys_fadvise64(args: &SyscallArgs) -> i64 {
    let fd     = args.a0 as i32;
    let offset = args.a1 as i64;
    let len    = args.a2 as i64;
    let advice = args.a3 as i32;

    let cur = match sched::live::current() { Some(c) => c, None => return err(Errno::Ebadf) };
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; Arc clone.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return err(Errno::Ebadf) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return err(Errno::Ebadf) };

    let inode = file.f_inode();
    let is_fifo = inode.file_type() == vfs::FileType::Fifo;
    // Linux's `!mapping` arm is unreachable for an fd that reached here: every
    // open file has an `f_mapping`. The oxide `i_mapping()` Option instead
    // reports whether a page-cache BACKEND exists, which corresponds to Linux's
    // `bdi == &noop_backing_dev_info` case — validate the advice, then return 0
    // without acting — not to `!mapping`.
    if let Err(e) = fadvise_check(is_fifo, true, offset, len, advice) { return err(e); }

    match advice {
        POSIX_FADV_NORMAL     => { file.ra_set_normal();     return 0; }
        POSIX_FADV_SEQUENTIAL => { file.ra_set_sequential(); return 0; }
        POSIX_FADV_RANDOM     => { file.ra_set_random();     return 0; }
        _ => {}
    }
    // POSIX_FADV_NOREUSE sets FMODE_NOREUSE in Linux, which only biases folio
    // activation during reclaim — no residency change, no error. Falls through
    // to the 0 below with the other non-residency advice.
    let mapping = match inode.i_mapping() { Some(m) => m, None => return 0 };
    let endbyte = endbyte_of(offset, len);

    match advice {
        POSIX_FADV_WILLNEED => {
            // Linux `force_page_cache_readahead(mapping, file, start_index,
            // nrpages)`: bring the range's pages into the cache. Already-
            // resident pages are skipped so a repeat hint costs nothing, and
            // the range is clamped to i_size because reading past EOF cannot
            // populate anything.
            let size = mapping.size();
            let end = core::cmp::min((endbyte as u64).saturating_add(1), size);
            let mut off = (offset as u64) & !(PAGE - 1);
            let mut page = alloc::vec![0u8; PAGE as usize];
            while off < end {
                if !mapping.mincore_page(off) { let _ = mapping.read_at(off, &mut page); }
                off = match off.checked_add(PAGE) { Some(n) => n, None => break };
            }
        }
        POSIX_FADV_DONTNEED => {
            // Linux flushes the range first (`filemap_flush_range`) so no dirty
            // data is lost, then invalidates. `writeback_range`/
            // `invalidate_range` take an EXCLUSIVE end; `endbyte` is inclusive.
            let end = (endbyte as u64).saturating_add(1);
            let _ = mapping.writeback_range(offset as u64, end);
            // `invalidate_range` already implements Linux's whole-page rule:
            // a page straddling either boundary is retained.
            let _ = mapping.invalidate_range(offset as u64, end);
        }
        _ => {}
    }
    0
}
