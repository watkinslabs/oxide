// The copy fallback's accounting and its short-run rule.
//
// These pin behaviour a caller OBSERVES: the statistics record it mapped and
// the notifications it armed. A run that counts buffers instead of operations,
// or that posts a shortage notification the allocation path already posts, is
// not a cosmetic difference — it is the difference between a caller being able
// to tune its refill rate and being told noise.

use super::*;
use alloc::vec::Vec;
use syscall::errno::Errno;

const PAGE: usize = 4096;

/// Run `total` bytes through buffers of `buf_len` with `budget` buffers
/// available, collecting the `(offset, len)` of every buffer placed.
fn run(total: usize, buf_len: usize, budget: usize)
    -> (Result<CopyReport, Errno>, Vec<(usize, usize)>)
{
    let mut placed = Vec::new();
    let mut left = budget;
    let r = copy_run(total, buf_len, |off, len| {
        if left == 0 { return false; }
        left -= 1;
        placed.push((off, len));
        true
    });
    (r, placed)
}

/// A run that fits in one buffer places it whole and counts one operation.
#[test]
fn a_run_inside_one_buffer_is_one_placement_and_one_operation() {
    let (r, placed) = run(100, PAGE, 8);
    assert_eq!(placed, alloc::vec![(0, 100)]);
    assert_eq!(r, Ok(CopyReport { copied: 100, copy_count: 1, copy_bytes: 100,
                                  notif: Some(ZCRX_NOTIF_COPY) }));
}

/// A run spanning several buffers is still ONE copy operation. Counting the
/// buffers would make the number a function of the buffer size the caller
/// registered rather than of how often the stack fell back to copying.
#[test]
fn a_run_spanning_several_buffers_counts_one_operation_not_one_per_buffer() {
    let (r, placed) = run(3 * PAGE, PAGE, 8);
    assert_eq!(placed, alloc::vec![(0, PAGE), (PAGE, PAGE), (2 * PAGE, PAGE)]);
    let rep = r.unwrap();
    assert_eq!(rep.copy_count, 1);
    assert_eq!(rep.copy_bytes, 3 * PAGE as u64);
    assert_eq!(rep.copied, 3 * PAGE);
}

/// The last buffer of a run takes only the remainder, never a whole buffer's
/// worth — a caller reading the completion's length past the bytes that
/// arrived would read whatever the buffer held before.
#[test]
fn the_last_buffer_of_a_run_takes_only_the_remainder() {
    let (r, placed) = run(PAGE + 7, PAGE, 8);
    assert_eq!(placed, alloc::vec![(0, PAGE), (PAGE, 7)]);
    assert_eq!(r.unwrap().copy_bytes, PAGE as u64 + 7);
}

/// Running out of buffers part-way is a SHORT copy that succeeds: the bytes
/// placed were delivered and their completions posted, and the receive resumes
/// once the caller refills. It posts the copy notification and NO shortage
/// notification — the shortage belongs to the allocation path a bound device
/// queue draws through, and reporting it here as well would tell a caller the
/// same thing twice per receive.
#[test]
fn a_run_that_exhausts_the_buffers_is_a_short_copy_with_no_extra_notification() {
    let (r, placed) = run(4 * PAGE, PAGE, 2);
    assert_eq!(placed, alloc::vec![(0, PAGE), (PAGE, PAGE)]);
    let rep = r.unwrap();
    assert_eq!(rep.copied, 2 * PAGE);
    assert_eq!(rep.copy_count, 1);
    assert_eq!(rep.notif, Some(ZCRX_NOTIF_COPY));
    assert_ne!(rep.notif, Some(ZCRX_NOTIF_NO_BUFFERS));
}

/// A run that could place nothing is the one failure, and it is `ENOMEM`.
/// Reporting zero bytes instead would be indistinguishable from a socket with
/// nothing on it, and the caller would wait for data it already has.
#[test]
fn a_run_with_no_buffers_at_all_reports_out_of_memory_and_counts_nothing() {
    let (r, placed) = run(4 * PAGE, PAGE, 0);
    assert!(placed.is_empty());
    assert_eq!(r, Err(Errno::Enomem));
}

/// An empty run is the same failure: nothing was placed, so there is nothing
/// to count and nothing to notify.
#[test]
fn an_empty_run_places_nothing_and_reports_out_of_memory() {
    let (r, placed) = run(0, PAGE, 8);
    assert!(placed.is_empty());
    assert_eq!(r, Err(Errno::Enomem));
}

/// A zero buffer size cannot make progress and must not spin looking for one.
#[test]
fn a_zero_buffer_size_terminates_rather_than_spinning() {
    let (r, placed) = run(PAGE, 0, 8);
    assert!(placed.is_empty());
    assert_eq!(r, Err(Errno::Enomem));
}

/// A shared-buffer area is refused with `EINVAL`, not with "unsupported".
/// This kernel has no buffer-sharing framework to import from, and the flag
/// stays RECOGNISED so the answer names the description rather than the bit.
#[test]
fn a_shared_buffer_area_is_recognised_and_reported_as_an_invalid_description() {
    let a = AreaReg { addr: 0, len: 8 * PAGE as u64, rq_area_token: 0,
                      flags: IORING_ZCRX_AREA_DMABUF, dmabuf_fd: 5, resv2: [0; 2] };
    assert_eq!(admit_area_reg(&a, PAGE as u64), Err(Errno::Einval));
    // And with an offset, which the reference refuses for such an area too.
    let mut a2 = a; a2.addr = PAGE as u64;
    assert_eq!(admit_area_reg(&a2, PAGE as u64), Err(Errno::Einval));
    // An UNKNOWN flag is a different answer from a recognised one: both are
    // `EINVAL` here, so the distinction is that the recognised flag survives
    // the supported-flag mask rather than being rejected by it.
    assert_eq!(IO_ZCRX_AREA_SUPPORTED_FLAGS & IORING_ZCRX_AREA_DMABUF,
               IORING_ZCRX_AREA_DMABUF);
}
