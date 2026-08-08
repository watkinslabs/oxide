//! Slots 310/311 `process_vm_readv`/`process_vm_writev` against Linux's
//! process-vm-access syscall bodies and the iovec import path they run
//! their two iov arrays through.
//!
//! The decision core is deliberately outside the `target_os = "oxide-kernel"`
//! slot files: a `#[cfg(test)] mod tests` inside `310_process_vm_readv.rs`
//! would compile out silently while cargo still prints "ok".

// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
use syscall::errno::Errno;

#[path = "../src/pvmrw_common/decide.rs"]
mod decide;

use decide::{
    check_all_seg_lens, check_seg_count, check_seg_len, decode_iov, finish, import_local,
    page_remaining, remote_pages, Lockstep, CHUNK_MAX, IOVEC_BYTES, MAX_RW_COUNT, UIO_MAXIOV,
};

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// A user address that is inside the user range on both arches.
const USER_BASE: u64 = 0x1000;
/// First address at or above `hal::USER_VA_END`.
const KERNEL_BASE: u64 = hal::USER_VA_END;

// ---------------------------------------------------------------- counts

#[test]
fn segment_count_ceiling_is_uio_maxiov() {
    assert_eq!(UIO_MAXIOV, 1024);
    assert_eq!(check_seg_count(0), Ok(()));
    assert_eq!(check_seg_count(1), Ok(()));
    assert_eq!(check_seg_count(UIO_MAXIOV), Ok(()));
    assert_eq!(check_seg_count(UIO_MAXIOV + 1), Err(eno(Errno::Einval)));
    assert_eq!(check_seg_count(usize::MAX), Err(eno(Errno::Einval)));
}

// --------------------------------------------------------------- lengths

#[test]
fn an_iov_len_that_does_not_fit_ssize_t_is_einval() {
    assert_eq!(check_seg_len(0), Ok(()));
    assert_eq!(check_seg_len(i64::MAX as u64), Ok(()));
    assert_eq!(check_seg_len(i64::MAX as u64 + 1), Err(eno(Errno::Einval)));
    assert_eq!(check_seg_len(u64::MAX), Err(eno(Errno::Einval)));
}

#[test]
fn every_segment_length_is_checked_before_any_address_rule() {
    // Linux `copy_iovec_from_user` walks the whole array rejecting bad
    // lengths before `__import_iovec` ever runs `access_ok`, so a bad length
    // in a TRAILING segment outranks a bad address in a LEADING one.
    let iovs = [(KERNEL_BASE, 16u64), (USER_BASE, u64::MAX)];
    assert_eq!(check_all_seg_lens(&iovs), Err(eno(Errno::Einval)));
    let mut ok = [(USER_BASE, 16u64), (USER_BASE, 16u64)];
    assert_eq!(check_all_seg_lens(&ok), Ok(()));
    assert!(import_local(&mut ok).is_ok());
}

// ---------------------------------------------------------------- decode

#[test]
fn iovec_wire_layout_is_base_then_len() {
    assert_eq!(IOVEC_BYTES, 16);
    let mut raw = [0u8; 32];
    raw[0..8].copy_from_slice(&0xdead_beefu64.to_ne_bytes());
    raw[8..16].copy_from_slice(&0x40u64.to_ne_bytes());
    raw[16..24].copy_from_slice(&0x1234u64.to_ne_bytes());
    raw[24..32].copy_from_slice(&0u64.to_ne_bytes());
    assert_eq!(decode_iov(&raw, 0), (0xdead_beef, 0x40));
    assert_eq!(decode_iov(&raw, 1), (0x1234, 0));
}

// ---------------------------------------------------------- local import

#[test]
fn local_import_rejects_an_address_outside_the_user_range() {
    let mut iovs = [(USER_BASE, 8u64), (KERNEL_BASE, 8u64)];
    assert_eq!(import_local(&mut iovs), Err(eno(Errno::Efault)));
    let mut null = [(0u64, 8u64), (USER_BASE, 8u64)];
    assert_eq!(import_local(&mut null), Err(eno(Errno::Efault)));
}

#[test]
fn local_import_totals_the_segments() {
    let mut iovs = [(USER_BASE, 8u64), (USER_BASE + 0x1000, 24u64), (USER_BASE, 0u64)];
    assert_eq!(import_local(&mut iovs), Ok(32));
    assert_eq!(iovs[2].1, 0);
}

#[test]
fn max_rw_count_truncates_the_local_total_it_never_rejects_it() {
    // Linux `__import_iovec` clamps `iov_len` and keeps going; there is no
    // EINVAL/EOVERFLOW arm for an oversized total.
    let big = MAX_RW_COUNT as u64;
    let mut iovs = [(USER_BASE, big), (USER_BASE + 0x1000_0000, big)];
    assert_eq!(import_local(&mut iovs), Ok(big));
    assert_eq!(iovs[0].1, big);
    assert_eq!(iovs[1].1, 0, "the second segment is truncated to nothing, not refused");
}

#[test]
fn a_single_local_segment_is_clamped_before_access_ok_a_pair_is_not() {
    // `import_ubuf` (nr_segs == 1) clamps to MAX_RW_COUNT and only then
    // calls access_ok; `__import_iovec` (nr_segs > 1) calls access_ok on the
    // UNCLAMPED length. Same length, different verdict — a real Linux quirk.
    let over = KERNEL_BASE; // base + over would leave the user range
    let mut one = [(USER_BASE, over)];
    assert_eq!(import_local(&mut one), Ok(MAX_RW_COUNT as u64));
    let mut two = [(USER_BASE, over), (USER_BASE, 8)];
    assert_eq!(import_local(&mut two), Err(eno(Errno::Efault)));
}

#[test]
fn an_empty_local_array_imports_zero_bytes() {
    let mut none: [(u64, u64); 0] = [];
    assert_eq!(import_local(&mut none), Ok(0));
    let mut empty = [(USER_BASE, 0u64), (USER_BASE, 0u64)];
    assert_eq!(import_local(&mut empty), Ok(0));
}

// --------------------------------------------------------- remote pages

#[test]
fn remote_pages_is_zero_only_when_every_remote_segment_is_empty() {
    assert_eq!(remote_pages(&[]), 0);
    assert_eq!(remote_pages(&[(USER_BASE, 0), (0, 0)]), 0);
    assert_eq!(remote_pages(&[(USER_BASE, 1)]), 1);
    // A one-byte span that straddles a page boundary needs two pages.
    assert_eq!(remote_pages(&[(0xfff, 2)]), 2);
    assert_eq!(remote_pages(&[(0x1000, 0x1000)]), 1);
    assert_eq!(remote_pages(&[(0x1000, 0x1001)]), 2);
    // Linux keeps the MAXIMUM across segments, not the sum.
    assert_eq!(remote_pages(&[(0x1000, 0x1000), (0x4000, 0x3000)]), 3);
}

// --------------------------------------------------------------- lockstep

fn drain(l: &[(u64, u64)], r: &[(u64, u64)]) -> Vec<(u64, u64, usize)> {
    let mut step = Lockstep::new();
    let mut out = Vec::new();
    while let Some(c) = step.next(l, r) {
        out.push((c.local, c.remote, c.len));
        step.advance(c.len);
    }
    out
}

#[test]
fn lockstep_splits_at_whichever_side_runs_out_first() {
    let l = [(0x1000, 16u64)];
    let r = [(0x9000, 4u64), (0xa000, 12u64)];
    assert_eq!(drain(&l, &r), vec![(0x1000, 0x9000, 4), (0x1004, 0xa000, 12)]);
}

#[test]
fn lockstep_stops_when_the_local_array_is_exhausted() {
    let l = [(0x1000, 4u64)];
    let r = [(0x9000, 64u64)];
    assert_eq!(drain(&l, &r), vec![(0x1000, 0x9000, 4)]);
}

#[test]
fn zero_length_segments_are_skipped_not_treated_as_terminators() {
    // The bug this pins: `if chunk == 0 { break }` silently truncated the
    // whole transfer at the first empty iovec on either side, where Linux's
    // iov_iter steps over it and `process_vm_rw_single_vec` returns 0.
    let l = [(0x1000, 0u64), (0x2000, 8u64)];
    let r = [(0x9000, 0u64), (0xa000, 4u64), (0xb000, 0u64), (0xc000, 4u64)];
    assert_eq!(drain(&l, &r), vec![(0x2000, 0xa000, 4), (0x2004, 0xc000, 4)]);
}

#[test]
fn a_partial_step_resumes_at_the_unmoved_remainder() {
    let l = [(0x1000, 16u64)];
    let r = [(0x9000, 16u64)];
    let mut step = Lockstep::new();
    let first = step.next(&l, &r).expect("first chunk");
    assert_eq!((first.local, first.remote, first.len), (0x1000, 0x9000, 16));
    step.advance(6);
    let second = step.next(&l, &r).expect("resumed chunk");
    assert_eq!((second.local, second.remote, second.len), (0x1006, 0x9006, 10));
}

#[test]
fn a_chunk_is_bounded_so_a_two_gib_iov_cannot_ask_for_a_two_gib_buffer() {
    let big = MAX_RW_COUNT as u64;
    let l = [(0x1000, big)];
    let r = [(0x1_0000_0000u64, big)];
    let mut step = Lockstep::new();
    let c = step.next(&l, &r).expect("chunk");
    assert_eq!(c.len, CHUNK_MAX);
    step.advance(c.len);
    let c2 = step.next(&l, &r).expect("chunk");
    assert_eq!(c2.local, 0x1000 + CHUNK_MAX as u64);
    assert_eq!(c2.remote, 0x1_0000_0000 + CHUNK_MAX as u64);
}

#[test]
fn an_empty_array_on_either_side_yields_no_chunks() {
    assert!(drain(&[], &[(0x9000, 8)]).is_empty());
    assert!(drain(&[(0x1000, 8)], &[]).is_empty());
}

// ----------------------------------------------------------------- tail

#[test]
fn bytes_transferred_outrank_a_later_error() {
    // `process_vm_rw_core`: `if (total_len) rc = total_len;`. Returning
    // -EFAULT from the middle of the loop after some bytes already moved is
    // the classic divergence.
    assert_eq!(finish(0, 0), 0);
    assert_eq!(finish(0, eno(Errno::Efault)), eno(Errno::Efault));
    assert_eq!(finish(1, eno(Errno::Efault)), 1);
    assert_eq!(finish(4096, eno(Errno::Efault)), 4096);
    assert_eq!(finish(4096, 0), 4096);
}

// ---------------------------------------------------------- page helper

#[test]
fn page_remaining_measures_to_the_end_of_the_page() {
    assert_eq!(page_remaining(0x1000), 4096);
    assert_eq!(page_remaining(0x1001), 4095);
    assert_eq!(page_remaining(0x1fff), 1);
}
