// The measurement list: an append-only sequence of records, each extended into
// a PCR as it is appended.
//
// Three distinctions decide whether an attestation quote means anything:
// the value extended is the record's TEMPLATE digest, not the file digest; it
// goes into the PCR the matching rule named, not always the default one; and a
// violation record extends a run of one-bits instead, so the PCR can never
// again match a good sequence.

use alloc::vec::Vec;

use crate::hash::HashAlgo;
use crate::limits::DEFAULT_MEASURE_PCR;
use crate::template::TemplateEntry;

/// The PCR-extend operation, owned by the TPM subsystem. IMA computes what to
/// extend and where; it does not implement the extend itself.
pub trait PcrExtend {
    /// Extend `pcr` in the bank for `algo` with `digest`. # C: O(1)
    fn extend(&mut self, pcr: u32, algo: HashAlgo, digest: &[u8]) -> Result<(), ()>;
}

/// Why an append did not add a record.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AppendError {
    /// An identical record already covers this PCR, so re-measuring it would
    /// add nothing and the record is dropped.
    Exists,
    /// Measurement is suspended, as it is once the TPM is shut down for reboot.
    Suspended,
    /// This kernel has no engine for the list's digest algorithm.
    NoAlgo,
}

/// A record as the list holds it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ListEntry {
    pub entry: TemplateEntry,
    /// Digest over the record's fields — the value extended into the PCR.
    pub template_digest: Vec<u8>,
    /// True when the record reports a violation rather than a measurement.
    pub violation: bool,
}

/// The measurement list and its counters.
pub struct MeasurementList {
    /// Digest algorithm the list's records and its deduplication key use.
    pub algo: HashAlgo,
    entries: Vec<ListEntry>,
    violations: u64,
    suspended: bool,
    /// Deduplication is by (record digest, PCR); disabling it keeps every
    /// re-measurement in the log.
    dedup: bool,
}

impl MeasurementList {
    /// An empty list measuring with `algo`. # C: O(1)
    pub fn new(algo: HashAlgo) -> Self {
        Self { algo, entries: Vec::new(), violations: 0, suspended: false, dedup: true }
    }

    /// Records, in append order. # C: O(1)
    pub fn entries(&self) -> &[ListEntry] { &self.entries }
    /// Number of records. # C: O(1)
    pub fn len(&self) -> usize { self.entries.len() }
    /// True when nothing has been measured. # C: O(1)
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    /// Violations counted since boot. # C: O(1)
    pub fn violations(&self) -> u64 { self.violations }
    /// Stop accepting records, as at TPM shutdown. # C: O(1)
    pub fn suspend(&mut self) { self.suspended = true; }
    /// Keep every re-measurement rather than deduplicating. # C: O(1)
    pub fn set_dedup(&mut self, on: bool) { self.dedup = on; }

    /// Is a record with this digest already covering this PCR? # C: O(n)
    pub fn contains(&self, digest: &[u8], pcr: u32) -> bool {
        self.entries.iter().any(|e| e.template_digest == digest && e.entry.pcr == pcr)
    }

    /// Append a measurement record and extend its PCR with the record's
    /// template digest. # C: O(n)
    pub fn add(&mut self, entry: TemplateEntry, tpm: &mut impl PcrExtend)
        -> Result<(), AppendError>
    {
        let digest = entry.template_digest(self.algo).ok_or(AppendError::NoAlgo)?;
        self.insert(entry, digest, false, tpm)
    }

    /// Append a violation record: counted, logged with a zero digest, and — so
    /// the PCR can never again match a good sequence — extended with one-bits
    /// rather than with the record's own digest. # C: O(n)
    pub fn add_violation(&mut self, entry: TemplateEntry, tpm: &mut impl PcrExtend)
        -> Result<(), AppendError>
    {
        self.violations += 1;
        let zero = alloc::vec![0u8; self.algo.size()];
        self.insert(entry, zero, true, tpm)
    }

    fn insert(&mut self, entry: TemplateEntry, digest: Vec<u8>, violation: bool,
              tpm: &mut impl PcrExtend) -> Result<(), AppendError>
    {
        if self.suspended { return Err(AppendError::Suspended); }
        if !violation && self.dedup && self.contains(&digest, entry.pcr) {
            return Err(AppendError::Exists);
        }
        let pcr = entry.pcr;
        self.entries.push(ListEntry { entry, template_digest: digest.clone(), violation });
        let extended = if violation { invalidating_digest(self.algo) } else { digest };
        // A TPM error leaves the record in the list: the log must show what was
        // measured even when the PCR could not be extended.
        let _ = tpm.extend(pcr, self.algo, &extended);
        Ok(())
    }
}

/// The value a violation extends: all one-bits, which no measurement can
/// produce, so the PCR is permanently invalidated. # C: O(1)
pub fn invalidating_digest(algo: HashAlgo) -> Vec<u8> {
    alloc::vec![0xffu8; algo.size()]
}

/// The TPM bank algorithm a measurement algorithm extends into. `None` when no
/// bank exists for it. # C: O(1)
pub fn bank_alg(algo: HashAlgo) -> Option<tpm::alg::Alg> {
    match algo {
        HashAlgo::Sha1 => Some(tpm::alg::Alg::Sha1),
        HashAlgo::Sha256 => Some(tpm::alg::Alg::Sha256),
        HashAlgo::Sha384 => Some(tpm::alg::Alg::Sha384),
        HashAlgo::Sha512 => Some(tpm::alg::Alg::Sha512),
        HashAlgo::Sm3_256 => Some(tpm::alg::Alg::Sm3),
        _ => None,
    }
}

/// A measurement extends the platform registers through the TPM subsystem's
/// own extend; nothing here re-implements it.
impl PcrExtend for tpm::pcr::Bank {
    /// # C: O(digest size)
    fn extend(&mut self, pcr: u32, algo: HashAlgo, digest: &[u8]) -> Result<(), ()> {
        if bank_alg(algo) != Some(self.alg()) { return Err(()); }
        tpm::pcr::Bank::extend(self, pcr as usize, digest).map_err(|_| ())
    }
}

/// Whether this measurement still needs storing, given which PCRs already hold
/// a measurement of this inode. A record carrying an appended module signature
/// is always stored, because the signature is only available at appraisal time
/// and an earlier record would not contain it. # C: O(1)
pub fn should_store(measured_pcrs: u64, pcr: u32, has_modsig: bool) -> bool {
    has_modsig || measured_pcrs & (1u64 << pcr) == 0
}

/// Record that this inode has been measured into `pcr`. # C: O(1)
pub fn note_measured(measured_pcrs: u64, pcr: u32) -> u64 { measured_pcrs | (1u64 << pcr) }

/// The PCR a rule's decision selects. # C: O(1)
pub fn pcr_for(rule_pcr: Option<u32>) -> u32 { rule_pcr.unwrap_or(DEFAULT_MEASURE_PCR) }

/// An integrity violation, named as the measurement list names it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Violation {
    /// A measured file already open for read was opened for write: what was
    /// measured is not what will be used.
    ToMToU,
    /// A file was opened for read while a writer holds it open: the digest
    /// about to be taken may not be of the bytes any reader sees.
    OpenWriters,
}

impl Violation {
    /// Cause string the violation record carries. # C: O(1)
    pub fn cause(self) -> &'static str {
        match self { Self::ToMToU => "ToMToU", Self::OpenWriters => "open_writers" }
    }
}

/// Per-inode state the violation check reads and updates.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct ViolationState {
    /// A reader has measured this inode, so a later writer is a ToMToU.
    pub may_emit_tomtou: bool,
    /// An open-writers violation has already been reported for this inode and
    /// is not reported again until every writer has closed.
    pub emitted_openwriters: bool,
}

/// The open that is being checked.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct OpenCheck {
    /// This open is for write.
    pub for_write: bool,
    /// Readers currently hold the inode open.
    pub readers: bool,
    /// Writers currently hold the inode open.
    pub open_for_write: bool,
    /// The inode is under measurement, so its PCR is worth invalidating.
    pub is_measured_inode: bool,
    /// Policy says this open is to be measured.
    pub must_measure: bool,
}

/// Decide which violations this open raises, updating the inode's state.
/// # C: O(1)
pub fn rdwr_violation_check(st: &mut ViolationState, c: OpenCheck) -> Vec<Violation> {
    let mut out = Vec::new();
    if c.for_write {
        if c.readers && c.is_measured_inode && st.may_emit_tomtou {
            st.may_emit_tomtou = false;
            out.push(Violation::ToMToU);
        }
    } else {
        if c.must_measure { st.may_emit_tomtou = true; }
        if c.open_for_write && c.must_measure && !st.emitted_openwriters {
            st.emitted_openwriters = true;
            out.push(Violation::OpenWriters);
        }
    }
    out
}

/// The last writer has closed, so an open-writers violation may be reported
/// again. # C: O(1)
pub fn last_writer_closed(st: &mut ViolationState) { st.emitted_openwriters = false; }

#[cfg(test)]
mod tests;
