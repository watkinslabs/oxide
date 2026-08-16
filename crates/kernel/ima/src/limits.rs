// Sizes, counts and slots the integrity ABI fixes.

/// Digest length the original `ima` template's `d` field reserves.
pub const IMA_DIGEST_SIZE: usize = 20;
/// Event-name length the original `ima` template's `n` field limits to. The
/// hashed form is this plus the terminating NUL.
pub const IMA_EVENT_NAME_LEN_MAX: usize = 255;
/// Largest digest any defined algorithm produces.
pub const IMA_MAX_DIGEST_SIZE: usize = 64;
/// Digest length a TPM event log entry carries for the SHA-1 bank.
pub const TPM_DIGEST_SIZE: usize = 20;
/// PCR the measurement list extends unless a rule says otherwise.
pub const DEFAULT_MEASURE_PCR: u32 = 10;
/// Number of PCRs a measured-PCR set can track; also the `pcr=` upper bound.
pub const PCR_COUNT: u32 = 64;
/// Maximum LSM conditions per rule (obj/subj × user/role/type).
pub const MAX_LSM_RULES: usize = 6;
/// Maximum fields in a template format.
pub const IMA_TEMPLATE_NUM_FIELDS_MAX: usize = 15;
/// Maximum characters in a template field identifier.
pub const IMA_TEMPLATE_FIELD_ID_MAX_LEN: usize = 16;

/// A `pcr=` value outside the trackable range is rejected. # C: O(1)
pub fn invalid_pcr(pcr: i64) -> bool { pcr < 0 || pcr >= PCR_COUNT as i64 }
