//! Bounded SCSI command descriptor blocks and operation-code constants.

use block::{BlockError, KResult};

/// TEST UNIT READY operation code. # C: O(1)
pub const TEST_UNIT_READY: u8 = 0x00;
/// INQUIRY operation code. # C: O(1)
pub const INQUIRY: u8 = 0x12;
/// READ CAPACITY(10) operation code. # C: O(1)
pub const READ_CAPACITY_10: u8 = 0x25;
/// READ(10) operation code. # C: O(1)
pub const READ_10: u8 = 0x28;
/// WRITE(10) operation code. # C: O(1)
pub const WRITE_10: u8 = 0x2a;
/// SYNCHRONIZE CACHE(10) operation code. # C: O(1)
pub const SYNCHRONIZE_CACHE_10: u8 = 0x35;
/// MODE SENSE(6), used to read the SCSI caching mode page.
pub const MODE_SENSE_6: u8 = 0x1a;
/// READ(16) operation code. # C: O(1)
pub const READ_16: u8 = 0x88;
/// WRITE(16) operation code. # C: O(1)
pub const WRITE_16: u8 = 0x8a;
/// SERVICE ACTION IN(16) operation code. # C: O(1)
pub const SERVICE_ACTION_IN_16: u8 = 0x9e;
/// READ CAPACITY(16) service action. # C: O(1)
pub const READ_CAPACITY_16: u8 = 0x10;

/// Read WCE from a MODE SENSE(6) caching page. `None` means the response was
/// absent or malformed, so a caller must retain a conservative barrier fact.
pub fn caching_mode_page_writeback(data: &[u8]) -> Option<bool> {
    if data.len() < 4 { return None; }
    let length = (usize::from(data[0]) + 1).min(data.len());
    let mut at = 4usize;
    while at + 2 <= length {
        let code = data[at] & 0x3f;
        let page_len = usize::from(data[at + 1]);
        let end = at.checked_add(2)?.checked_add(page_len)?;
        if end > length { return None; }
        if code == 0x08 {
            return (page_len >= 3).then(|| data[at + 2] & 0x04 != 0);
        }
        at = end;
    }
    None
}

/// Largest CDB accepted by the shared SCSI layer. Individual transports may
/// expose a lower SG_IO limit. # C: O(1)
pub const MAX_CDB_BYTES: usize = 32;

/// A bounded SCSI CDB. The mid-layer owns its bytes, so a transport never
/// receives a pointer into a transient block request. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Command { bytes: [u8; MAX_CDB_BYTES], len: u8 }

impl Command {
    /// Make a CDB from its exact wire bytes. # C: O(CDB bytes)
    pub fn new(bytes: &[u8]) -> KResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_CDB_BYTES { return Err(BlockError::Einval); }
        let mut cdb = [0u8; MAX_CDB_BYTES];
        cdb[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { bytes: cdb, len: bytes.len() as u8 })
    }

    /// Full CDB wire bytes, excluding the zero-filled tail. # C: O(1)
    pub fn bytes(&self) -> &[u8] { &self.bytes[..self.len as usize] }

    /// Operation code. # C: O(1)
    pub fn opcode(&self) -> u8 { self.bytes[0] }

    fn fixed(bytes: &[u8]) -> Self {
        let mut cdb = [0u8; MAX_CDB_BYTES];
        cdb[..bytes.len()].copy_from_slice(bytes);
        Self { bytes: cdb, len: bytes.len() as u8 }
    }

    /// Fixed INQUIRY command for the standard 36-byte response. # C: O(1)
    pub(crate) fn inquiry() -> Self { Self::fixed(&[INQUIRY, 0, 0, 0, 36, 0]) }

    /// Fixed READ CAPACITY(10) command. # C: O(1)
    pub(crate) fn capacity_10() -> Self { Self::fixed(&[READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0]) }

    /// Fixed SERVICE ACTION IN(16)/READ CAPACITY(16) command. # C: O(1)
    pub(crate) fn capacity_16() -> Self {
        Self::fixed(&[SERVICE_ACTION_IN_16, READ_CAPACITY_16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }
}

#[cfg(test)]
mod tests {
    use super::caching_mode_page_writeback;

    #[test]
    fn caching_page_reports_wce_and_skips_other_pages() {
        let mut page = [0u8; 16];
        page[0] = 15;
        page[4..8].copy_from_slice(&[0x01, 2, 0xaa, 0xbb]);
        page[8..14].copy_from_slice(&[0x08, 4, 0x04, 0, 0, 0]);
        assert_eq!(caching_mode_page_writeback(&page), Some(true));
        page[10] = 0;
        assert_eq!(caching_mode_page_writeback(&page), Some(false));
    }
}
