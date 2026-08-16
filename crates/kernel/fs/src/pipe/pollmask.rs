// `pipe_poll` — the readiness mask ONE OPEN END of a pipe reports.
//
// A pipe's readiness is per-end, not per-inode: the reference computes the
// read-side bits only when the description is readable and the write-side bits
// only when it is writable, and the two ends report DIFFERENT things about the
// same condition. The end that matters here is the read end losing its last
// writer: that is a HANGUP, and a consumer that polls for nothing but
// `POLLHUP` — which is what a wait-for-the-writer-to-go-away looks like, since
// `POLLHUP` cannot be requested in `events` and is only ever reported — sees
// the event immediately on the reference and never at all when the mask is
// computed for the inode instead of for the end.
//
// Ungated and pure so the whole table is hosted-testable (`docs/53`); the ring
// supplies the four counters and the two direction bits.

use vfs::{POLL_ERR, POLL_HUP, POLL_IN, POLL_OUT, POLL_RDNORM, POLL_WRNORM};

/// Readiness for one open end.
///
/// * read end — data queued is readable; NO writer left is a hangup.
/// * write end — room in the ring is writable; NO reader left is an error,
///   not a hangup (the two sides of a broken pipe report different bits).
///
/// `readable`/`writable` are the description's access mode, so an `O_RDWR`
/// FIFO end reports both halves, exactly as the reference does for a file
/// carrying both `FMODE_READ` and `FMODE_WRITE`.
/// # C: O(1)
pub fn pipe_poll_mask(
    readable: bool,
    writable: bool,
    len: usize,
    cap: usize,
    readers: usize,
    writers: usize,
) -> u32 {
    let mut mask = 0u32;
    if readable {
        if len > 0 { mask |= POLL_IN | POLL_RDNORM; }
        if writers == 0 { mask |= POLL_HUP; }
    }
    if writable {
        if len < cap { mask |= POLL_OUT | POLL_WRNORM; }
        if readers == 0 { mask |= POLL_ERR; }
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP: usize = 65536;

    #[test]
    fn a_read_end_whose_last_writer_closed_reports_a_hangup() {
        // The whole reason a Type=idle service start takes its timeout instead
        // of proceeding at once: the consumer polls a pipe read end for
        // nothing but a hangup.
        let m = pipe_poll_mask(true, false, 0, CAP, 1, 0);
        assert_eq!(m & POLL_HUP, POLL_HUP, "read end must report HUP once no writer is left");
    }

    #[test]
    fn a_read_end_with_a_writer_and_no_data_is_not_ready_at_all() {
        assert_eq!(pipe_poll_mask(true, false, 0, CAP, 1, 1), 0);
    }

    #[test]
    fn a_read_end_reports_data_with_the_normal_band_bit() {
        assert_eq!(pipe_poll_mask(true, false, 1, CAP, 1, 1), POLL_IN | POLL_RDNORM);
    }

    #[test]
    fn a_drained_read_end_still_reports_data_and_hangup_together() {
        // Bytes written before the writer left are still readable, and the
        // hangup is reported alongside them rather than instead of them.
        let m = pipe_poll_mask(true, false, 8, CAP, 1, 0);
        assert_eq!(m, POLL_IN | POLL_RDNORM | POLL_HUP);
    }

    #[test]
    fn a_read_end_never_reports_the_write_sides_error() {
        // No reader left is the WRITE end's condition. Reporting it on the
        // read end is what made the read end unable to report its own.
        assert_eq!(pipe_poll_mask(true, false, 0, CAP, 0, 1) & POLL_ERR, 0);
    }

    #[test]
    fn a_write_end_with_no_reader_reports_error_and_never_hangup() {
        let m = pipe_poll_mask(false, true, 0, CAP, 0, 1);
        assert_eq!(m & POLL_ERR, POLL_ERR);
        assert_eq!(m & POLL_HUP, 0, "a broken pipe is an error on the write end, not a hangup");
    }

    #[test]
    fn a_write_end_with_room_is_writable() {
        assert_eq!(pipe_poll_mask(false, true, 0, CAP, 1, 1), POLL_OUT | POLL_WRNORM);
    }

    #[test]
    fn a_full_write_end_is_not_writable() {
        assert_eq!(pipe_poll_mask(false, true, CAP, CAP, 1, 1), 0);
    }

    #[test]
    fn a_write_end_never_reports_readability() {
        assert_eq!(pipe_poll_mask(false, true, 42, CAP, 1, 1) & (POLL_IN | POLL_RDNORM), 0);
    }

    #[test]
    fn a_bidirectional_fifo_end_reports_both_halves() {
        let m = pipe_poll_mask(true, true, 4, CAP, 1, 1);
        assert_eq!(m, POLL_IN | POLL_RDNORM | POLL_OUT | POLL_WRNORM);
    }

    #[test]
    fn an_end_open_for_neither_direction_reports_nothing() {
        assert_eq!(pipe_poll_mask(false, false, 4, CAP, 0, 0), 0);
    }
}
