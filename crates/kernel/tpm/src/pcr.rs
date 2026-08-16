// Platform configuration registers: the extend arithmetic and the bank state
// it mutates.
//
// A PCR is a one-way accumulator. Extending replaces its value with
// H(current || measurement), digest-sized for the bank's own algorithm. Two
// properties carry the whole security argument and both are easy to break
// silently:
//
//   - the operand ORDER. H(measurement || current) is also a hash, also the
//     right length, and also updates on every event — but it is forgeable,
//     because an attacker who controls the first block controls the chain.
//   - the WIDTH. A digest padded or truncated to another bank's length still
//     hashes; it just measures something other than what was presented.
//
// Both are enforced here rather than at call sites, and both carry positive
// controls in the test module.

use alloc::vec;
use alloc::vec::Vec;

use crate::alg::Alg;
use crate::limits::{MAX_PCR_BANKS, PLATFORM_PCR};

/// Why a PCR is being returned to a reset value.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ResetCause {
    /// Power-on or a startup that discards state: every PCR takes the reset
    /// value its index defines.
    TpmReset,
    /// A dynamic root of trust measurement begins: the DRTM registers take
    /// zero, every other register is untouched.
    DrtmStart,
    /// An explicit reset command issued from `locality`.
    Command(u8),
}

/// Why a PCR operation was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PcrError {
    /// Index is outside the platform's PCR range.
    BadIndex(usize),
    /// Digest length does not match the bank's algorithm.
    BadDigestLen { expected: usize, got: usize },
    /// No bank of this algorithm is allocated.
    UnknownBank(u16),
    /// An allocated bank received no digest in an agile extend.
    MissingBank(u16),
    /// The bank's algorithm cannot be computed by this kernel.
    UnsupportedAlg(u16),
    /// The register cannot be reset from this locality.
    NotResettable { index: usize, locality: u8 },
    /// More banks were requested than the platform tracks, or a duplicate.
    BadBankSet,
}

/// Lowest index of the dynamic-root-of-trust register range.
pub const DRTM_PCR_FIRST: usize = 17;
/// Highest index of the dynamic-root-of-trust register range.
pub const DRTM_PCR_LAST: usize = 22;
/// Debug register: resettable from any locality.
pub const DEBUG_PCR: usize = 16;
/// Application register: resettable from any locality.
pub const APPLICATION_PCR: usize = 23;
/// Locality that owns the dynamic root of trust.
pub const DRTM_LOCALITY: u8 = 4;
/// Fill byte a register holding a static measurement takes at TPM reset.
const RESET_FILL_STATIC: u8 = 0x00;
/// Fill byte a dynamic-root register takes at TPM reset, distinguishing
/// "never entered a measured launch" from "measured launch produced zero".
const RESET_FILL_DRTM: u8 = 0xFF;

/// Fill byte index `idx` takes at TPM reset. # C: O(1)
pub fn reset_fill(idx: usize) -> u8 {
    if (DRTM_PCR_FIRST..=DRTM_PCR_LAST).contains(&idx) { RESET_FILL_DRTM } else { RESET_FILL_STATIC }
}

/// Whether index `idx` may be reset by command from `locality`. # C: O(1)
pub fn is_resettable(idx: usize, locality: u8) -> bool {
    if idx >= PLATFORM_PCR { return false; }
    match idx {
        DEBUG_PCR | APPLICATION_PCR => true,
        DRTM_PCR_FIRST..=DRTM_PCR_LAST => locality == DRTM_LOCALITY,
        _ => false,
    }
}

/// New PCR value from an old one and a measurement: H(old || measurement).
///
/// Both operands must already be the bank's digest length; a caller holding a
/// digest of another width has a bug this refuses to paper over.
/// # C: O(digest size)
pub fn extend_value(alg: Alg, old: &[u8], measurement: &[u8]) -> Result<Vec<u8>, PcrError> {
    let n = alg.digest_size();
    if old.len() != n { return Err(PcrError::BadDigestLen { expected: n, got: old.len() }); }
    if measurement.len() != n { return Err(PcrError::BadDigestLen { expected: n, got: measurement.len() }); }
    match alg.hash(&[old, measurement]) {
        Some(v) => Ok(v),
        None => Err(PcrError::UnsupportedAlg(alg.id())),
    }
}

/// One bank: the full set of platform registers under a single algorithm.
pub struct Bank {
    alg: Alg,
    /// PLATFORM_PCR registers laid end to end, each `alg.digest_size()` wide.
    values: Vec<u8>,
}

impl Bank {
    /// Bank at its TPM-reset state. # C: O(PLATFORM_PCR × digest size)
    pub fn new(alg: Alg) -> Self {
        let mut b = Bank { alg, values: vec![0u8; PLATFORM_PCR * alg.digest_size()] };
        b.reset_all(ResetCause::TpmReset);
        b
    }

    /// Algorithm of this bank. # C: O(1)
    pub fn alg(&self) -> Alg { self.alg }

    fn span(&self, idx: usize) -> Result<core::ops::Range<usize>, PcrError> {
        if idx >= PLATFORM_PCR { return Err(PcrError::BadIndex(idx)); }
        let n = self.alg.digest_size();
        Ok(idx * n..idx * n + n)
    }

    /// Current value of register `idx`. # C: O(1)
    pub fn read(&self, idx: usize) -> Result<&[u8], PcrError> { Ok(&self.values[self.span(idx)?]) }

    /// Replace register `idx` with H(current || measurement).
    /// # C: O(digest size)
    pub fn extend(&mut self, idx: usize, measurement: &[u8]) -> Result<(), PcrError> {
        let span = self.span(idx)?;
        let next = extend_value(self.alg, &self.values[span.clone()], measurement)?;
        self.values[span].copy_from_slice(&next);
        Ok(())
    }

    /// Return register `idx` to a reset value, if `cause` permits.
    /// # C: O(digest size)
    pub fn reset(&mut self, idx: usize, cause: ResetCause) -> Result<(), PcrError> {
        let span = self.span(idx)?;
        let fill = match cause {
            ResetCause::TpmReset => reset_fill(idx),
            ResetCause::DrtmStart => {
                if !(DRTM_PCR_FIRST..=DRTM_PCR_LAST).contains(&idx) { return Ok(()); }
                RESET_FILL_STATIC
            }
            ResetCause::Command(loc) => {
                if !is_resettable(idx, loc) { return Err(PcrError::NotResettable { index: idx, locality: loc }); }
                RESET_FILL_STATIC
            }
        };
        self.values[span].fill(fill);
        Ok(())
    }

    /// Apply `cause` to every register that it touches.
    /// # C: O(PLATFORM_PCR × digest size)
    pub fn reset_all(&mut self, cause: ResetCause) {
        for idx in 0..PLATFORM_PCR {
            // A whole-bank reset skips registers the cause does not authorise
            // rather than failing; per-register refusal is `reset`.
            let _ = self.reset(idx, cause);
        }
    }
}

/// Every allocated bank. One event extends all of them, each with the digest
/// computed under that bank's own algorithm — the crypto-agile contract.
pub struct Banks {
    banks: Vec<Bank>,
}

impl Banks {
    /// Allocate one bank per algorithm, in the order given.
    /// # C: O(banks × PLATFORM_PCR × digest size)
    pub fn new(algs: &[Alg]) -> Result<Self, PcrError> {
        if algs.is_empty() || algs.len() > MAX_PCR_BANKS { return Err(PcrError::BadBankSet); }
        for (i, a) in algs.iter().enumerate() {
            if algs[..i].contains(a) { return Err(PcrError::BadBankSet); }
        }
        Ok(Banks { banks: algs.iter().map(|a| Bank::new(*a)).collect() })
    }

    /// Allocated algorithms, in allocation order. # C: O(banks)
    pub fn algs(&self) -> Vec<Alg> { self.banks.iter().map(|b| b.alg()).collect() }

    /// Number of allocated banks. # C: O(1)
    pub fn len(&self) -> usize { self.banks.len() }

    /// Whether no bank is allocated. # C: O(1)
    pub fn is_empty(&self) -> bool { self.banks.is_empty() }

    /// Bank of algorithm `alg`. # C: O(banks)
    pub fn bank(&self, alg: Alg) -> Result<&Bank, PcrError> {
        self.banks.iter().find(|b| b.alg() == alg).ok_or(PcrError::UnknownBank(alg.id()))
    }

    /// Read register `idx` from the bank of algorithm `alg`. # C: O(banks)
    pub fn read(&self, alg: Alg, idx: usize) -> Result<&[u8], PcrError> { self.bank(alg)?.read(idx) }

    /// Extend register `idx` in EVERY allocated bank.
    ///
    /// `digests` pairs an algorithm identifier with the measurement computed
    /// under it. Every allocated bank must appear: a caller that supplies one
    /// digest leaves the other banks recording a different history, so the
    /// missing bank is an error rather than a skipped update.
    /// # C: O(banks × digest size)
    pub fn extend(&mut self, idx: usize, digests: &[(u16, &[u8])]) -> Result<(), PcrError> {
        if idx >= PLATFORM_PCR { return Err(PcrError::BadIndex(idx)); }
        for b in self.banks.iter() {
            if !digests.iter().any(|(id, _)| *id == b.alg().id()) { return Err(PcrError::MissingBank(b.alg().id())); }
        }
        for (id, _) in digests.iter() {
            if !self.banks.iter().any(|b| b.alg().id() == *id) { return Err(PcrError::UnknownBank(*id)); }
        }
        // Validate every operand before mutating any bank, so a rejected
        // request leaves no bank half-extended.
        for b in self.banks.iter() {
            let d = digests.iter().find(|(id, _)| *id == b.alg().id()).map(|(_, d)| *d).unwrap_or(&[]);
            let n = b.alg().digest_size();
            if d.len() != n { return Err(PcrError::BadDigestLen { expected: n, got: d.len() }); }
            if b.alg().digest_impl().is_none() { return Err(PcrError::UnsupportedAlg(b.alg().id())); }
        }
        for b in self.banks.iter_mut() {
            let d = digests.iter().find(|(id, _)| *id == b.alg().id()).map(|(_, d)| *d).unwrap_or(&[]);
            b.extend(idx, d)?;
        }
        Ok(())
    }

    /// Apply `cause` to every bank. # C: O(banks × PLATFORM_PCR × digest size)
    pub fn reset_all(&mut self, cause: ResetCause) { for b in self.banks.iter_mut() { b.reset_all(cause); } }

    /// Reset register `idx` in every bank, refusing if `cause` forbids it.
    /// # C: O(banks × digest size)
    pub fn reset(&mut self, idx: usize, cause: ResetCause) -> Result<(), PcrError> {
        if let ResetCause::Command(loc) = cause {
            if !is_resettable(idx, loc) { return Err(PcrError::NotResettable { index: idx, locality: loc }); }
        }
        for b in self.banks.iter_mut() { b.reset(idx, cause)?; }
        Ok(())
    }
}
