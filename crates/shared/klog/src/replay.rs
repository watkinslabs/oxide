// Replay of buffered records into a console that registers late (Linux
// `CON_PRINTBUFFER` — a console is fed the records already in the log buffer
// at registration, which is why a serial console brought up by device init
// still shows the whole boot and not just the part after itself).
//
// The ring is byte-addressed by a monotonic total-stream position
// (`crate::ring_total`), so "what this wire has already shown" is one cursor
// and the replay is the half-open range `[shown_through, total)`.

/// Bytes moved per `ring_read` call. Small on purpose: replay runs with the
/// console lock held and the aarch64 stack budget has no margin, so the buffer
/// is a fixed local rather than a fraction of the 64 KiB ring.
const CHUNK_BYTES: usize = 256;

/// Where a console registering now should start reading.
///
/// `shown_through` is the position this wire has already displayed, or `None`
/// when nothing has ever displayed on it — the registering console is then the
/// first, and gets everything the ring still holds. `oldest` is the floor:
/// bytes before it were overwritten and no longer exist to replay.
/// # C: O(1)
pub fn init_console_cursor(shown_through: Option<usize>, oldest: usize) -> usize {
    match shown_through {
        Some(s) if s > oldest => s,
        _ => oldest,
    }
}

/// Feed the ring's `[from, total)` range into `f` and return the position
/// reached. Writes only to `f` — a replay is for the console that just
/// registered, not for the ones that already showed these bytes.
/// # C: O(total - from)
pub fn replay_into(f: crate::LogSink, from: usize) -> usize {
    let mut cursor = from;
    let mut buf = [0u8; CHUNK_BYTES];
    loop {
        let (n, next) = crate::ring_read(cursor, &mut buf);
        if n == 0 { return next; }
        f(&buf[..n]);
        cursor = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_console_replays_everything_the_ring_holds() {
        assert_eq!(init_console_cursor(None, 0), 0, "nothing shown, nothing overwritten: from the start");
        assert_eq!(init_console_cursor(None, 4096), 4096, "overwritten bytes cannot be replayed");
    }

    #[test]
    fn a_wire_that_has_shown_output_resumes_from_there() {
        assert_eq!(init_console_cursor(Some(900), 0), 900, "no double-print of what the wire already showed");
        assert_eq!(init_console_cursor(Some(900), 4096), 4096, "the overwrite floor still wins");
        assert_eq!(init_console_cursor(Some(4096), 4096), 4096);
    }

    #[test]
    fn replay_moves_the_whole_range_and_stops() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        let _g = crate::console::test_lock();
        static SEEN: AtomicUsize = AtomicUsize::new(0);
        fn sink(b: &[u8]) { SEEN.fetch_add(b.len(), Ordering::Relaxed); }

        // A range longer than one chunk, so the loop's own advance is exercised.
        crate::clear_byte_sink();
        crate::clear_aux_sink();
        let start = crate::ring_total();
        // Newline-terminated: an unterminated write leaves the line assembler
        // mid-line, and the next test's first line then loses its timestamp.
        let mut line = [b'x'; CHUNK_BYTES + 7];
        line[CHUNK_BYTES + 6] = b'\n';
        crate::write_raw(&line);
        let end = crate::ring_total();

        SEEN.store(0, Ordering::Relaxed);
        let reached = replay_into(sink, start);
        assert_eq!(SEEN.load(Ordering::Relaxed), end - start, "every buffered byte reaches the new console");
        assert_eq!(reached, end, "replay reports the position it reached");

        SEEN.store(0, Ordering::Relaxed);
        let again = replay_into(sink, end);
        assert_eq!(SEEN.load(Ordering::Relaxed), 0, "replaying from the end emits nothing");
        assert_eq!(again, end);
    }
}
