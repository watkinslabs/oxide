// LZ77 match finding for the encoder.
//
// Hash-chain greedy parser: every position's 4-byte prefix is hashed into a
// bucket, and each bucket threads a chain of earlier positions. Searching walks
// that chain up to a depth the level chooses and keeps the longest match.
//
// Greedy rather than optimal on purpose. zram compresses one page on the swap
// path, where a parser that spends ten times the CPU for a few percent of ratio
// is the wrong trade -- and an optimal parser needs a cost model, which needs
// the entropy tables, which is a second pass over the block.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

/// Bytes hashed per position. Also the shortest match the finder will report:
/// a 3-byte match rarely pays for its own sequence overhead.
pub const MIN_MATCH: usize = 4;
/// Hash table size, as a power of two. A page is 4 KiB, so 4096 buckets makes
/// collisions rare without the table costing more than the data.
const HASH_LOG: u32 = 12;
const HASH_SIZE: usize = 1 << HASH_LOG;
/// Knuth's multiplicative constant, the same one libzstd uses.
const HASH_MULT: u32 = 2_654_435_761;
/// Chain entry meaning "no earlier position".
const NO_POS: u32 = u32::MAX;

/// One LZ77 match: copy `length` bytes from `distance` back.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Match {
    pub distance: usize,
    pub length: usize,
}

pub struct Finder {
    head: Vec<u32>,
    chain: Vec<u32>,
    depth: usize,
}

fn hash4(src: &[u8], at: usize) -> usize {
    let v = u32::from_le_bytes([src[at], src[at + 1], src[at + 2], src[at + 3]]);
    (v.wrapping_mul(HASH_MULT) >> (32 - HASH_LOG)) as usize
}

impl Finder {
    /// `depth` is how many chain entries a search visits before giving up.
    /// # C: O(len)
    pub fn new(len: usize, depth: usize) -> Self {
        Self { head: vec![NO_POS; HASH_SIZE], chain: vec![NO_POS; len], depth }
    }

    /// Record `at` as the most recent position for its hash.
    /// # C: O(1)
    pub fn insert(&mut self, src: &[u8], at: usize) {
        if at + MIN_MATCH > src.len() { return; }
        let h = hash4(src, at);
        self.chain[at] = self.head[h];
        self.head[h] = at as u32;
    }

    /// Longest match for the data at `at`, searching only positions already
    /// inserted. Returns `None` below `MIN_MATCH`.
    /// # C: O(depth * match length)
    pub fn find(&self, src: &[u8], at: usize) -> Option<Match> {
        if at + MIN_MATCH > src.len() { return None; }
        let h = hash4(src, at);
        let mut candidate = self.head[h];
        let mut best: Option<Match> = None;
        let mut left = self.depth;
        while candidate != NO_POS && left > 0 {
            let pos = candidate as usize;
            if pos >= at { break; }
            let len = common_prefix(src, pos, at);
            if len >= MIN_MATCH {
                // Strictly longer only: among equal lengths the nearest
                // candidate wins, and the chain is walked nearest-first, so a
                // shorter distance is already preferred.
                let better = best.is_none_or(|b| len > b.length);
                if better { best = Some(Match { distance: at - pos, length: len }); }
            }
            candidate = self.chain[pos];
            left -= 1;
        }
        best
    }
}

/// Length of the common run starting at `a` and `b`, stopping at the end of
/// input. `b` is ahead of `a`, so the run may overlap `b` itself -- which is
/// legal and is how runs compress.
/// # C: O(length)
fn common_prefix(src: &[u8], a: usize, b: usize) -> usize {
    let mut n = 0;
    while b + n < src.len() && src[a + n] == src[b + n] { n += 1; }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(src: &[u8], depth: usize) -> Finder {
        let mut f = Finder::new(src.len(), depth);
        for i in 0..src.len() { f.insert(src, i); }
        f
    }

    #[test]
    fn a_repeated_block_is_found_at_the_right_distance() {
        let src = b"abcdefgh_abcdefgh";
        let mut f = Finder::new(src.len(), 16);
        for i in 0..9 { f.insert(src, i); }
        let m = f.find(src, 9).expect("the repeat is found");
        assert_eq!(m.distance, 9);
        assert_eq!(m.length, 8);
    }

    #[test]
    fn a_run_matches_through_itself() {
        // Distance 1 over a run is the overlapping case: the match extends
        // past its own start, which is what makes `aaaa...` compress.
        let src = b"aaaaaaaaaa";
        let mut f = Finder::new(src.len(), 16);
        f.insert(src, 0);
        let m = f.find(src, 1).expect("the run is found");
        assert_eq!(m.distance, 1);
        assert_eq!(m.length, 9, "the match runs to the end of input");
    }

    #[test]
    fn nothing_shorter_than_the_minimum_is_reported() {
        let src = b"abcXabZZZZZZ";
        let f = build(src, 16);
        // "abc" vs "abZ" shares three bytes, below the minimum.
        let mut f2 = Finder::new(src.len(), 16);
        for i in 0..4 { f2.insert(src, i); }
        assert_eq!(f2.find(src, 4), None);
        let _ = f;
    }

    #[test]
    fn the_search_never_looks_forward() {
        let src = b"abcdabcd";
        let f = build(src, 16);
        // Position 0 has nothing before it even though a later copy exists.
        assert_eq!(f.find(src, 0), None);
    }

    #[test]
    fn a_shallow_search_still_returns_a_valid_match() {
        // Depth 1 may miss the LONGEST match, but whatever it returns must
        // still be a real one -- a wrong distance corrupts silently.
        let src = b"xxxxABCDxxxxABCDEFGHxxxxABCDEFGH";
        let f = build(src, 1);
        for at in 0..src.len() {
            if let Some(m) = f.find(src, at) {
                assert!(m.distance <= at);
                assert_eq!(&src[at - m.distance..at - m.distance + m.length],
                    &src[at..at + m.length], "reported match must actually match");
            }
        }
    }
}
