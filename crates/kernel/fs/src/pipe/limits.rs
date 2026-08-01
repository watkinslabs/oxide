// Sizes a pipe ring is bound by.
//
// Three DIFFERENT numbers that a single `PIPE_CAP` constant used to conflate,
// which is why a pipe could neither hold a real payload nor be resized:
//   * how much a fresh pipe may hold          — [`PIPE_DEF_SIZE`]
//   * how far `F_SETPIPE_SZ` may raise that   — [`PIPE_MAX_SIZE`]
//   * how large a write is still ATOMIC       — [`PIPE_BUF`]
// Only the last is a POSIX guarantee; the first two are tunables.

/// Bytes a pipe holds before a writer has to wait, for a pipe nobody resized.
/// Sixteen pages, which is what `F_GETPIPE_SZ` reports on a fresh pipe and what
/// a core dump written to a helper's standard input relies on: a 4 KiB ring
/// turns a multi-megabyte dump into thousands of round trips through the
/// scheduler, each of which is a chance for the dumping thread to be aborted.
pub const PIPE_DEF_SIZE: usize = 16 * PAGE;

/// Ceiling `F_SETPIPE_SZ` may raise a pipe to without `CAP_SYS_RESOURCE`
/// (`/proc/sys/fs/pipe-max-size`). A request above it is `EPERM`, not a clamp —
/// silently handing back a smaller pipe than asked for would make a program
/// that sized its pipe for a batch deadlock on the batch.
pub const PIPE_MAX_SIZE: usize = 1024 * PAGE;

/// POSIX `PIPE_BUF`. A write of at most this many bytes is delivered whole or
/// not at all, so two writers cannot interleave inside one message. Larger
/// writes carry no such guarantee and may be split.
pub const PIPE_BUF: usize = PAGE;

/// Granularity the ring's backing allocation grows in. A pipe that only ever
/// carries a line of text keeps one page, the way a pipe whose buffers are
/// allocated on demand does — the capacity above is a ceiling, not a
/// reservation.
pub const PIPE_GROW_STEP: usize = PAGE;

const PAGE: usize = 4096;

/// Round a requested pipe size up to whole [`PIPE_GROW_STEP`] units, with one
/// unit as the floor. `F_SETPIPE_SZ` never produces a pipe smaller than a page,
/// and never one whose capacity is not a whole number of allocation units.
/// # C: O(1)
pub const fn round_pipe_size(requested: usize) -> usize {
    if requested <= PIPE_GROW_STEP { return PIPE_GROW_STEP; }
    let units = requested.div_ceil(PIPE_GROW_STEP);
    units * PIPE_GROW_STEP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_pipe_holds_sixteen_pages_and_stays_atomic_for_one() {
        assert_eq!(PIPE_DEF_SIZE, 65536);
        assert_eq!(PIPE_BUF, 4096);
        assert!(PIPE_DEF_SIZE > PIPE_BUF, "a pipe must hold more than one atomic write");
        assert!(PIPE_MAX_SIZE > PIPE_DEF_SIZE);
    }

    #[test]
    fn a_requested_size_rounds_up_to_whole_allocation_units() {
        assert_eq!(round_pipe_size(0), PIPE_GROW_STEP);
        assert_eq!(round_pipe_size(1), PIPE_GROW_STEP);
        assert_eq!(round_pipe_size(PIPE_GROW_STEP), PIPE_GROW_STEP);
        assert_eq!(round_pipe_size(PIPE_GROW_STEP + 1), 2 * PIPE_GROW_STEP);
        assert_eq!(round_pipe_size(PIPE_DEF_SIZE), PIPE_DEF_SIZE);
    }

    #[test]
    fn rounding_never_reports_less_than_was_asked_for() {
        for r in [1usize, 7, 4095, 4097, 12345, 65535, 999_999] {
            assert!(round_pipe_size(r) >= r, "{r}");
        }
    }
}
