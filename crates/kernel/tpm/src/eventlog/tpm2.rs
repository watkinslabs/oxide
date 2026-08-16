// Crypto-agile records. A record's length is not stored anywhere: it is
// computed by walking a count-prefixed digest list whose entries are sized by
// the log's own algorithm table, then reading a length-prefixed event blob.
//
// That walk is the whole attack surface of the log. A count field larger than
// the table, an algorithm identifier the table does not size, or an event
// size longer than the buffer each cause a naive walk to read past the end,
// and the resulting "record" is whatever memory followed. Every one of those
// is refused here, and the refusals are pinned by tests that feed truncated
// and count-inflated records.

use alloc::vec::Vec;

use super::cursor::LeCursor;
use super::error::LogError;
use super::spec_id::SpecId;

/// One crypto-agile record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Event2<'a> {
    pub pcr_idx: u32,
    pub event_type: u32,
    /// One digest per allocated bank, in the order the record carries them.
    pub digests: Vec<(u16, &'a [u8])>,
    pub event: &'a [u8],
    /// Bytes this record occupies.
    pub record_len: usize,
}

impl<'a> Event2<'a> {
    /// Parse the record at the start of `buf`, sized by the log's algorithm
    /// table. `LogError::EndOfLog` marks the terminator rather than a record.
    /// # C: O(digests + event length)
    pub fn parse(buf: &'a [u8], spec: &SpecId) -> Result<Event2<'a>, LogError> {
        let mut c = LeCursor::new(buf);
        let pcr_idx = c.u32()?;
        let event_type = c.u32()?;
        let count = c.u32()? as usize;
        // The record must carry exactly the banks the log declared: fewer
        // means a bank went unmeasured, more means the extra digests are
        // sized by a table that never described them.
        if count != spec.algs.len() { return Err(LogError::DigestCount { expected: spec.algs.len(), got: count }); }
        let mut digests = Vec::with_capacity(count);
        for _ in 0..count {
            let alg_id = c.u16()?;
            let n = spec.digest_size(alg_id)?;
            digests.push((alg_id, c.bytes(n)?));
        }
        let event_size = c.u32()? as usize;
        let event = c.bytes(event_size)?;
        if event_type == 0 && event_size == 0 { return Err(LogError::EndOfLog); }
        Ok(Event2 { pcr_idx, event_type, digests, event, record_len: c.offset() })
    }

    /// Digest recorded for `alg_id`, if the record carries that bank.
    /// # C: O(digests)
    pub fn digest(&self, alg_id: u16) -> Option<&'a [u8]> {
        self.digests.iter().find(|(a, _)| *a == alg_id).map(|(_, d)| *d)
    }
}

/// A crypto-agile log: its first record plus the records that follow.
pub struct Tpm2Log<'a> {
    buf: &'a [u8],
    spec: SpecId,
}

impl<'a> Tpm2Log<'a> {
    /// Parse the log header. # C: O(algorithms)
    pub fn parse(buf: &'a [u8]) -> Result<Tpm2Log<'a>, LogError> {
        let spec = SpecId::parse(buf)?;
        Ok(Tpm2Log { buf, spec })
    }

    /// The log's algorithm table. # C: O(1)
    pub fn spec(&self) -> &SpecId { &self.spec }

    /// Records after the header, in order. Iteration stops at the log
    /// terminator or at the first record that does not parse — never past
    /// the end of the buffer. # C: O(1) per step
    pub fn events(&self) -> Tpm2Events<'a, '_> {
        Tpm2Events { buf: self.buf, spec: &self.spec, off: self.spec.record_len }
    }
}

/// Iterator over a crypto-agile log's records.
pub struct Tpm2Events<'a, 's> {
    buf: &'a [u8],
    spec: &'s SpecId,
    off: usize,
}

impl<'a, 's> Iterator for Tpm2Events<'a, 's> {
    type Item = Event2<'a>;

    fn next(&mut self) -> Option<Event2<'a>> {
        if self.off >= self.buf.len() { return None; }
        match Event2::parse(&self.buf[self.off..], self.spec) {
            Ok(e) => { self.off += e.record_len; Some(e) }
            Err(_) => { self.off = self.buf.len(); None }
        }
    }
}
