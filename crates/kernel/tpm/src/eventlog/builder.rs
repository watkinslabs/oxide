// Log builders. A builder emits exactly what the matching parser accepts, so
// a round trip through both is a check on each: the digest table the header
// declares is the table every appended record is validated against, and a
// record whose digests do not match it is refused at append time rather than
// producing a log that only fails when someone walks it.

use alloc::vec::Vec;

use super::error::LogError;
use super::spec_id::{AlgSize, SPEC_ID_SIGNATURE};
use super::types::{EV_NO_ACTION, TCG_EVENT1_DIGEST_LEN};

/// Builds a crypto-agile log.
pub struct Tpm2LogBuilder {
    buf: Vec<u8>,
    algs: Vec<AlgSize>,
}

impl Tpm2LogBuilder {
    /// Start a log whose records carry the given banks, in this order.
    /// # C: O(algorithms)
    pub fn new(platform_class: u32, minor: u8, major: u8, errata: u8, uintn_size: u8,
               algs: &[AlgSize], vendor_info: &[u8]) -> Result<Self, LogError> {
        if algs.is_empty() { return Err(LogError::NoAlgorithms); }
        let mut ev: Vec<u8> = Vec::new();
        ev.extend_from_slice(SPEC_ID_SIGNATURE.as_slice());
        ev.extend_from_slice(&platform_class.to_le_bytes());
        ev.push(minor);
        ev.push(major);
        ev.push(errata);
        ev.push(uintn_size);
        ev.extend_from_slice(&(algs.len() as u32).to_le_bytes());
        for a in algs { ev.extend_from_slice(&a.alg_id.to_le_bytes()); ev.extend_from_slice(&a.digest_size.to_le_bytes()); }
        ev.push(vendor_info.len() as u8);
        ev.extend_from_slice(vendor_info);

        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&EV_NO_ACTION.to_le_bytes());
        buf.extend_from_slice(&[0u8; TCG_EVENT1_DIGEST_LEN]);
        buf.extend_from_slice(&(ev.len() as u32).to_le_bytes());
        buf.extend_from_slice(&ev);
        Ok(Tpm2LogBuilder { buf, algs: algs.to_vec() })
    }

    /// Append one record. Every declared bank must be present exactly once,
    /// at its declared width. # C: O(digests + event length)
    pub fn append(&mut self, pcr_idx: u32, event_type: u32, digests: &[(u16, &[u8])], event: &[u8])
        -> Result<(), LogError> {
        if digests.len() != self.algs.len() { return Err(LogError::DigestCount { expected: self.algs.len(), got: digests.len() }); }
        for a in self.algs.iter() {
            let d = digests.iter().find(|(id, _)| *id == a.alg_id).ok_or(LogError::UnknownAlg(a.alg_id))?.1;
            if d.len() != a.digest_size as usize {
                return Err(LogError::DigestLen { alg_id: a.alg_id, expected: a.digest_size as usize, got: d.len() });
            }
        }
        self.buf.extend_from_slice(&pcr_idx.to_le_bytes());
        self.buf.extend_from_slice(&event_type.to_le_bytes());
        self.buf.extend_from_slice(&(self.algs.len() as u32).to_le_bytes());
        for a in self.algs.iter() {
            let d = digests.iter().find(|(id, _)| *id == a.alg_id).expect("validated above").1;
            self.buf.extend_from_slice(&a.alg_id.to_le_bytes());
            self.buf.extend_from_slice(d);
        }
        self.buf.extend_from_slice(&(event.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(event);
        Ok(())
    }

    /// The log as written so far. # C: O(1)
    pub fn as_bytes(&self) -> &[u8] { &self.buf }

    /// Take the log. # C: O(1)
    pub fn finish(self) -> Vec<u8> { self.buf }
}

/// Builds a fixed-format log.
pub struct Tpm1LogBuilder {
    buf: Vec<u8>,
}

impl Default for Tpm1LogBuilder { fn default() -> Self { Self::new() } }

impl Tpm1LogBuilder {
    /// Start an empty log. # C: O(1)
    pub fn new() -> Self { Tpm1LogBuilder { buf: Vec::new() } }

    /// Append one record. # C: O(event length)
    pub fn append(&mut self, pcr_idx: u32, event_type: u32, digest: &[u8], event: &[u8]) -> Result<(), LogError> {
        if digest.len() != TCG_EVENT1_DIGEST_LEN {
            return Err(LogError::DigestLen { alg_id: 0, expected: TCG_EVENT1_DIGEST_LEN, got: digest.len() });
        }
        self.buf.extend_from_slice(&pcr_idx.to_le_bytes());
        self.buf.extend_from_slice(&event_type.to_le_bytes());
        self.buf.extend_from_slice(digest);
        self.buf.extend_from_slice(&(event.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(event);
        Ok(())
    }

    /// The log as written so far. # C: O(1)
    pub fn as_bytes(&self) -> &[u8] { &self.buf }

    /// Take the log. # C: O(1)
    pub fn finish(self) -> Vec<u8> { self.buf }
}
