// Pushing a dump out one chunk at a time.
//
// Every destination writes the same way: hand the next chunk to a sink that may
// take all of it, take some of it, or refuse. A dump is worth having even when
// it is cut short — a debugger reads a truncated core — so a refusal ends the
// delivery rather than discarding what already landed. What is NEVER acceptable
// is calling a truncated delivery a complete one, which is why the outcome
// carries both the byte count and whether the whole body got through.

/// What one chunk handed to a destination did.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Chunk {
    /// Bytes accepted. Fewer than offered is normal for a destination that
    /// takes what fits and expects the rest to be re-offered.
    Took(usize),
    /// Nothing more will be accepted: the size limit was reached, the reader
    /// went away, or the write failed.
    Refused,
}

/// How much of a dump reached its destination.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Delivery {
    /// Bytes the destination accepted.
    pub written: usize,
    /// Whether every byte of the body got through.
    pub complete: bool,
}

/// Feed `body` to `sink` in pieces of at most `chunk` bytes.
///
/// A sink that takes zero bytes without refusing is treated as a refusal: it
/// would otherwise be offered the same chunk forever, which is a hang inside
/// the exit path of a process that is already dying.
/// # C: O(len / chunk) calls, O(len) bytes
pub fn deliver(body: &[u8], chunk: usize, sink: &mut impl FnMut(&[u8]) -> Chunk) -> Delivery {
    if chunk == 0 { return Delivery { written: 0, complete: body.is_empty() }; }
    let mut off = 0usize;
    while off < body.len() {
        let end = (off + chunk).min(body.len());
        match sink(&body[off..end]) {
            Chunk::Took(0) | Chunk::Refused => break,
            Chunk::Took(n) => off += n.min(end - off),
        }
    }
    Delivery { written: off, complete: off == body.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn body(n: usize) -> Vec<u8> { (0..n).map(|i| (i % 251) as u8).collect() }

    #[test]
    fn a_sink_that_takes_everything_gets_the_whole_body_in_order() {
        let b = body(10_000);
        let mut got: Vec<u8> = Vec::new();
        let d = deliver(&b, 4096, &mut |c| { got.extend_from_slice(c); Chunk::Took(c.len()) });
        assert_eq!(d, Delivery { written: b.len(), complete: true });
        assert_eq!(got, b);
    }

    #[test]
    fn short_writes_are_re_offered_until_the_body_is_through() {
        let b = body(10_000);
        let mut got: Vec<u8> = Vec::new();
        // Takes at most 7 bytes per call, the way a nearly-full ring does.
        let d = deliver(&b, 4096, &mut |c| {
            let n = c.len().min(7);
            got.extend_from_slice(&c[..n]);
            Chunk::Took(n)
        });
        assert_eq!(d, Delivery { written: b.len(), complete: true });
        assert_eq!(got, b, "a short write must not drop the remainder of its chunk");
    }

    #[test]
    fn a_refusal_part_way_reports_a_truncated_delivery_not_a_complete_one() {
        let b = body(10_000);
        let mut taken = 0usize;
        let d = deliver(&b, 1000, &mut |c| {
            if taken >= 4000 { return Chunk::Refused; }
            taken += c.len();
            Chunk::Took(c.len())
        });
        assert_eq!(d, Delivery { written: 4000, complete: false });
    }

    #[test]
    fn a_sink_that_accepts_nothing_ends_the_delivery_instead_of_spinning() {
        let b = body(4096);
        let mut calls = 0usize;
        let d = deliver(&b, 512, &mut |_| { calls += 1; Chunk::Took(0) });
        assert_eq!(calls, 1, "an unproductive sink is offered a chunk exactly once");
        assert_eq!(d, Delivery { written: 0, complete: false });
    }

    #[test]
    fn an_empty_body_is_complete_without_touching_the_sink() {
        let mut calls = 0usize;
        let d = deliver(&[], 4096, &mut |_| { calls += 1; Chunk::Took(0) });
        assert_eq!(calls, 0);
        assert_eq!(d, Delivery { written: 0, complete: true });
    }

    #[test]
    fn a_sink_claiming_more_than_it_was_offered_cannot_run_past_the_body() {
        let b = body(100);
        let d = deliver(&b, 10, &mut |c| Chunk::Took(c.len() * 4));
        assert_eq!(d, Delivery { written: 100, complete: true });
    }

    #[test]
    fn the_last_chunk_is_short_when_the_body_does_not_divide_evenly() {
        let b = body(4500);
        let mut sizes: Vec<usize> = Vec::new();
        let d = deliver(&b, 4096, &mut |c| { sizes.push(c.len()); Chunk::Took(c.len()) });
        assert_eq!(sizes, alloc::vec![4096, 404]);
        assert!(d.complete);
    }
}
