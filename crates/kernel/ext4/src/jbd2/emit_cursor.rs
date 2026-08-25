/// Write-side cursor over the journal log.
/// Tracks the next-free journal block and never returns block zero.
#[derive(Copy, Clone, Debug)]
pub struct LogCursor {
    pub head:  u32,
    pub first: u32,
    pub maxlen: u32,
    pub seq:     u32,
}

impl LogCursor {
    /// # C: O(1)
    pub fn new(start: u32, first: u32, maxlen: u32, seq: u32) -> Self {
        let first = core::cmp::max(first, 1);
        let head = if start < first || start >= maxlen { first } else { start };
        Self { head, first, maxlen, seq }
    }

    /// Reserve `n` journal-block slots, wrapping after `maxlen`.
    /// # C: O(1)
    pub fn reserve(&mut self, n: u32) -> u32 {
        let first = self.head;
        let range = self.maxlen.saturating_sub(self.first) as u64;
        if range != 0 {
            let off = (self.head - self.first) as u64;
            self.head = self.first + ((off + n as u64) % range) as u32;
        }
        first
    }

    /// Number of usable log slots excluding the reserved prefix.
    /// # C: O(1)
    pub fn usable(&self) -> u32 { self.maxlen.saturating_sub(self.first) }

    /// Bump the transaction sequence after a commit lands.
    /// # C: O(1)
    pub fn bump_seq(&mut self) { self.seq = self.seq.wrapping_add(1); }
}

