// Platform configuration registers, as a DRIVER sees them.
//
// The kernel does not hold PCR values. A PCR lives in the chip, and the only
// way to change one is to send it a command; the only way to read one is to
// ask. What the kernel keeps is the bank INVENTORY — which algorithms the chip
// allocated and how wide each digest is — because that is what it needs to
// validate a caller's digest set before marshalling a command.
//
// This file used to hold a `Vec<u8>` of register contents and mutate it in
// place. That is a TPM simulator, not a TPM driver: a measurement extended
// into it never reached hardware, so a measured boot built on it would attest
// nothing while every test stayed green. The reference has no such structure,
// no reset semantics and no resettability table — those are chip-internal
// behaviour the kernel never models. All of it is gone.
//
// What remains is the one piece a driver genuinely needs: `extend_value`, the
// hash chain H(old || measurement), used to compute the value a log entry
// PREDICTS a register will hold, so a verifier can replay a measurement log
// and compare against what the chip reports. Two properties carry the whole
// security argument and both break silently:
//
//   - operand ORDER. H(measurement || old) is also a hash, also the right
//     length, and also changes on every event — but it is forgeable, because
//     an attacker who controls the first block controls the chain.
//   - digest WIDTH. A digest padded or truncated to another bank's length
//     still hashes; it just measures something other than what was presented.
//
// Both are enforced here rather than at call sites, and both carry positive
// controls in the test module.

use alloc::vec::Vec;

use crate::alg::Alg;
use crate::limits::{MAX_PCR_BANKS, PLATFORM_PCR};

/// Why a PCR operation was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PcrError {
    /// Index is outside the platform's PCR range.
    BadIndex(usize),
    /// Digest length does not match the bank's algorithm.
    BadDigestLen { expected: usize, got: usize },
    /// No bank of this algorithm is allocated on the chip.
    UnknownBank(u16),
    /// An allocated bank received no digest in an agile extend.
    MissingBank(u16),
    /// The bank's algorithm cannot be computed by this kernel.
    UnsupportedAlg(u16),
    /// More banks were reported than the platform tracks, or a duplicate.
    BadBankSet,
}

/// New PCR value from an old one and a measurement: H(old || measurement).
///
/// This computes what a register is EXPECTED to hold after an event, for
/// replaying a measurement log. It does not change any register — only the
/// chip can do that, through `Chip::pcr_extend`.
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

/// One bank the chip reports as allocated: its algorithm and digest width.
///
/// Metadata only. Mirrors the reference's per-bank record, which likewise
/// carries an algorithm id and a digest size and never a register value.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct BankInfo {
    alg: Alg,
}

impl BankInfo {
    /// Record a bank of algorithm `alg`. # C: O(1)
    pub fn new(alg: Alg) -> Self { BankInfo { alg } }

    /// Algorithm this bank hashes under. # C: O(1)
    pub fn alg(&self) -> Alg { self.alg }

    /// Wire identifier of the algorithm. # C: O(1)
    pub fn alg_id(&self) -> u16 { self.alg.id() }

    /// Digest width in bytes. # C: O(1)
    pub fn digest_size(&self) -> usize { self.alg.digest_size() }
}

/// The set of banks a chip reports as allocated, in the order it reported them.
///
/// An extend must supply one digest per allocated bank, because the chip
/// extends every bank from a single command and a caller who supplies fewer
/// leaves the omitted banks recording a different history.
pub struct AllocatedBanks {
    banks: Vec<BankInfo>,
}

impl AllocatedBanks {
    /// Record the banks a chip reported, in allocation order. # C: O(banks²)
    pub fn new(algs: &[Alg]) -> Result<Self, PcrError> {
        if algs.is_empty() || algs.len() > MAX_PCR_BANKS { return Err(PcrError::BadBankSet); }
        for (i, a) in algs.iter().enumerate() {
            if algs[..i].contains(a) { return Err(PcrError::BadBankSet); }
        }
        Ok(AllocatedBanks { banks: algs.iter().map(|a| BankInfo::new(*a)).collect() })
    }

    /// Allocated banks, in allocation order. # C: O(1)
    pub fn banks(&self) -> &[BankInfo] { &self.banks }

    /// Allocated algorithms, in allocation order. # C: O(banks)
    pub fn algs(&self) -> Vec<Alg> { self.banks.iter().map(|b| b.alg()).collect() }

    /// Number of allocated banks. # C: O(1)
    pub fn len(&self) -> usize { self.banks.len() }

    /// Whether no bank is allocated. # C: O(1)
    pub fn is_empty(&self) -> bool { self.banks.is_empty() }

    /// The allocated bank of algorithm `alg`. # C: O(banks)
    pub fn bank(&self, alg: Alg) -> Result<&BankInfo, PcrError> {
        self.banks.iter().find(|b| b.alg() == alg).ok_or(PcrError::UnknownBank(alg.id()))
    }

    /// Check a caller's digest set against the allocated banks, before any
    /// command is marshalled.
    ///
    /// The reference refuses an extend whose digest algorithms do not line up
    /// with the allocated banks rather than sending a partial command, and so
    /// does this: every allocated bank must be present, no unknown bank may
    /// appear, and every digest must be its bank's exact width.
    /// # C: O(banks × digests)
    pub fn check_extend(&self, idx: usize, digests: &[(u16, &[u8])]) -> Result<(), PcrError> {
        if idx >= PLATFORM_PCR { return Err(PcrError::BadIndex(idx)); }
        for b in self.banks.iter() {
            if !digests.iter().any(|(id, _)| *id == b.alg_id()) { return Err(PcrError::MissingBank(b.alg_id())); }
        }
        for (id, _) in digests.iter() {
            if !self.banks.iter().any(|b| b.alg_id() == *id) { return Err(PcrError::UnknownBank(*id)); }
        }
        for b in self.banks.iter() {
            let d = digests.iter().find(|(id, _)| *id == b.alg_id()).map(|(_, d)| *d).unwrap_or(&[]);
            if d.len() != b.digest_size() { return Err(PcrError::BadDigestLen { expected: b.digest_size(), got: d.len() }); }
        }
        Ok(())
    }
}
