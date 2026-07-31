// `RLIMIT_CORE`: how much of a core dump reaches its destination.
//
// Two independent decisions, both Linux's:
//   * a FILE destination with a zero limit produces no dump at all, while a
//     PIPE destination ignores the limit entirely (the helper program, not a
//     filesystem, receives the bytes);
//   * every emitted chunk is admitted only while the running total stays
//     within the limit, so an over-limit dump is TRUNCATED at a chunk
//     boundary rather than refused outright.

use super::INFINITY;

/// Linux `dump_emit`: `if (cprm->written + nr > cprm->limit) return 0;`.
/// A chunk that would cross the limit is refused whole — the dump stops there
/// rather than writing a partial chunk.
/// # C: O(1)
pub fn emit_admits(written: u64, nr: u64, limit: u64) -> bool {
    if limit == INFINITY { return true; }
    written.saturating_add(nr) <= limit
}

/// Bytes of a `body_len`-byte dump a chunked emitter delivers before the first
/// refused chunk. `chunk` is the emitter's granularity (Linux dumps page at a
/// time past the headers), so the result is always a whole number of chunks —
/// except for a final short chunk that still fits.
/// # C: O(1)
pub fn prefix_len(body_len: usize, limit: u64, chunk: usize) -> usize {
    if limit == INFINITY { return body_len; }
    if chunk == 0 { return 0; }
    let whole = (limit / chunk as u64).saturating_mul(chunk as u64);
    let capped = whole.min(body_len as u64);
    // A trailing partial chunk is emitted only if the WHOLE of it fits.
    let tail = (body_len as u64) - capped;
    if tail > 0 && capped.saturating_add(tail) <= limit { body_len } else { capped as usize }
}

/// Whether a FILE-destination dump happens at all. Linux refuses before it
/// opens anything when the soft limit is zero; a pipe destination never
/// consults the limit, because `cprm->limit` is overwritten with
/// `RLIM_INFINITY` once the helper is chosen.
/// # C: O(1)
pub const fn file_dump_enabled(limit: u64) -> bool { limit != 0 }

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 4096;

    #[test]
    fn a_zero_limit_disables_a_file_dump() {
        assert!(!file_dump_enabled(0));
        assert!(file_dump_enabled(1));
        assert!(file_dump_enabled(INFINITY));
    }

    #[test]
    fn emit_refuses_the_chunk_that_would_cross_the_limit() {
        assert!(emit_admits(0, PAGE as u64, PAGE as u64));
        assert!(!emit_admits(1, PAGE as u64, PAGE as u64));
        assert!(emit_admits(u64::MAX - 1, u64::MAX, INFINITY));
    }

    #[test]
    fn an_over_limit_dump_truncates_at_a_chunk_boundary() {
        // 10 pages of dump under a 4.5-page limit: four whole pages land, the
        // fifth is refused whole.
        let limit = (4 * PAGE + PAGE / 2) as u64;
        assert_eq!(prefix_len(10 * PAGE, limit, PAGE), 4 * PAGE);
    }

    #[test]
    fn a_dump_inside_the_limit_is_delivered_whole() {
        assert_eq!(prefix_len(3 * PAGE + 17, (10 * PAGE) as u64, PAGE), 3 * PAGE + 17);
        assert_eq!(prefix_len(3 * PAGE + 17, INFINITY, PAGE), 3 * PAGE + 17);
    }

    #[test]
    fn a_short_final_chunk_lands_only_if_it_fits_entirely() {
        // Body is one page plus 100 bytes; a limit of one page + 50 keeps only
        // the whole page.
        assert_eq!(prefix_len(PAGE + 100, (PAGE + 50) as u64, PAGE), PAGE);
        assert_eq!(prefix_len(PAGE + 100, (PAGE + 100) as u64, PAGE), PAGE + 100);
    }

    #[test]
    fn a_zero_limit_emits_nothing() {
        assert_eq!(prefix_len(10 * PAGE, 0, PAGE), 0);
    }
}
