// Fixed-format records: a 32-byte header carrying one 20-byte digest, then a
// length-prefixed event blob. The length field is still firmware-supplied, so
// it is bounded against the buffer before it is trusted; the log ends at a
// record whose type and size are both zero, or as soon as a record would run
// past the end.

use super::cursor::LeCursor;
use super::error::LogError;
use super::types::{TCG_EVENT1_DIGEST_LEN, TCG_EVENT1_HEADER_LEN};

/// One fixed-format record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Event1<'a> {
    pub pcr_idx: u32,
    pub event_type: u32,
    pub digest: &'a [u8],
    pub event: &'a [u8],
    /// Bytes this record occupies.
    pub record_len: usize,
}

impl<'a> Event1<'a> {
    /// Parse the record at the start of `buf`. `LogError::EndOfLog` marks the
    /// terminator rather than a record. # C: O(event length)
    pub fn parse(buf: &'a [u8]) -> Result<Event1<'a>, LogError> {
        let mut c = LeCursor::new(buf);
        let pcr_idx = c.u32()?;
        let event_type = c.u32()?;
        let digest = c.bytes(TCG_EVENT1_DIGEST_LEN)?;
        let event_size = c.u32()? as usize;
        if event_type == 0 && event_size == 0 { return Err(LogError::EndOfLog); }
        let event = c.bytes(event_size)?;
        Ok(Event1 { pcr_idx, event_type, digest, event, record_len: TCG_EVENT1_HEADER_LEN + event_size })
    }
}

/// A fixed-format log.
pub struct Tpm1Log<'a> {
    buf: &'a [u8],
}

impl<'a> Tpm1Log<'a> {
    /// Wrap a log buffer. # C: O(1)
    pub fn new(buf: &'a [u8]) -> Self { Tpm1Log { buf } }

    /// Records in order. # C: O(1) per step
    pub fn events(&self) -> Tpm1Events<'a> { Tpm1Events { buf: self.buf, off: 0 } }
}

/// Iterator over a fixed-format log's records.
pub struct Tpm1Events<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Iterator for Tpm1Events<'a> {
    type Item = Event1<'a>;

    fn next(&mut self) -> Option<Event1<'a>> {
        if self.off >= self.buf.len() { return None; }
        match Event1::parse(&self.buf[self.off..]) {
            Ok(e) => { self.off += e.record_len; Some(e) }
            Err(_) => { self.off = self.buf.len(); None }
        }
    }
}
