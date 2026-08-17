// The log's first record. It is a fixed-format record whose payload declares
// which banks the rest of the log carries and how wide each one is — so every
// later record can only be walked once this one has been parsed. A log whose
// first record fails these checks is not a crypto-agile log and must not be
// walked as one.

use alloc::vec::Vec;

use super::cursor::LeCursor;
use super::error::LogError;
use super::types::{EV_NO_ACTION, TCG_EVENT1_DIGEST_LEN, TCG_EVENT1_HEADER_LEN};

/// Signature the first record's payload carries, terminating NUL included.
pub const SPEC_ID_SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";

/// One entry of the log's algorithm table.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AlgSize {
    pub alg_id: u16,
    pub digest_size: u16,
}

/// The parsed first record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpecId {
    pub platform_class: u32,
    pub spec_version_minor: u8,
    pub spec_version_major: u8,
    pub spec_errata: u8,
    pub uintn_size: u8,
    pub algs: Vec<AlgSize>,
    pub vendor_info_len: u8,
    /// Bytes this record occupies, so the walk knows where record two starts.
    pub record_len: usize,
}

impl SpecId {
    /// Parse the first record of a log. # C: O(algorithms)
    pub fn parse(buf: &[u8]) -> Result<SpecId, LogError> {
        let mut c = LeCursor::new(buf);
        if c.u32()? != 0 { return Err(LogError::BadHeader("first record names a register other than 0")); }
        if c.u32()? != EV_NO_ACTION { return Err(LogError::BadHeader("first record is not a no-action event")); }
        if c.bytes(TCG_EVENT1_DIGEST_LEN)?.iter().any(|b| *b != 0) {
            return Err(LogError::BadHeader("first record carries a non-zero digest"));
        }
        let event_size = c.u32()? as usize;
        let event = c.bytes(event_size)?;
        let record_len = TCG_EVENT1_HEADER_LEN + event_size;

        let mut e = LeCursor::new(event);
        if e.bytes(SPEC_ID_SIGNATURE.len())? != SPEC_ID_SIGNATURE.as_slice() { return Err(LogError::BadSignature); }
        let platform_class = e.u32()?;
        let spec_version_minor = e.u8()?;
        let spec_version_major = e.u8()?;
        let spec_errata = e.u8()?;
        let uintn_size = e.u8()?;
        let num_algs = e.u32()? as usize;
        if num_algs == 0 { return Err(LogError::NoAlgorithms); }
        let mut algs = Vec::with_capacity(num_algs);
        for _ in 0..num_algs {
            let alg_id = e.u16()?;
            let digest_size = e.u16()?;
            algs.push(AlgSize { alg_id, digest_size });
        }
        let vendor_info_len = e.u8()?;
        e.skip(vendor_info_len as usize)?;

        Ok(SpecId {
            platform_class, spec_version_minor, spec_version_major, spec_errata, uintn_size,
            algs, vendor_info_len, record_len,
        })
    }

    /// Width of `alg_id` per this log's own table. A record naming an
    /// algorithm absent from the table cannot be walked at all — its digest
    /// length is unknown, so everything after it would be misread.
    /// # C: O(algorithms)
    pub fn digest_size(&self, alg_id: u16) -> Result<usize, LogError> {
        self.algs.iter().find(|a| a.alg_id == alg_id)
            .map(|a| a.digest_size as usize)
            .ok_or(LogError::UnknownAlg(alg_id))
    }
}
