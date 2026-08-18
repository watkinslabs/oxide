//! Common SCSI sense normalization and block-command recovery admission.
//!
//! The common layer classifies a completed command but never spins or sleeps:
//! the concrete host owns the process-context wait that makes a delayed retry
//! real. Raw SG_IO deliberately bypasses this module and receives the original
//! completion and sense bytes.

use crate::CommandCompletion;

const SAM_STAT_GOOD: u8 = 0x00;
const SAM_STAT_CHECK_CONDITION: u8 = 0x02;
const SAM_STAT_COMMAND_TERMINATED: u8 = 0x22;
const SAM_STAT_BUSY: u8 = 0x08;
const SAM_STAT_TASK_SET_FULL: u8 = 0x28;
const SAM_STAT_TASK_ABORTED: u8 = 0x40;

const NO_SENSE: u8 = 0x00;
const RECOVERED_ERROR: u8 = 0x01;
const NOT_READY: u8 = 0x02;
const UNIT_ATTENTION: u8 = 0x06;

/// Linux `sd`'s default maximum number of block-command retries. # C: O(1)
pub const DEFAULT_RETRIES: u8 = 5;
/// Linux's queue-restart delay for a device that has temporarily blocked. # C: O(1)
pub const QUEUE_RETRY_DELAY_MS: u32 = 3;
/// Linux's ALUA transition reprepare delay. # C: O(1)
pub const ALUA_TRANSITION_DELAY_MS: u32 = 1_000;

/// The normalized fixed- or descriptor-format SCSI sense header.
///
/// This retains the same five fields Linux derives in `scsi_normalize_sense`,
/// so callers do not accidentally interpret one wire format as the other.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SenseHeader {
    response_code: u8,
    sense_key: u8,
    asc: u8,
    ascq: u8,
    additional_length: u8,
}

impl SenseHeader {
    /// Normalize valid fixed (0x70/0x71) or descriptor (0x72/0x73) sense.
    /// Fields absent from a truncated, but valid, response remain zero exactly
    /// as in Linux's common SCSI normalizer. # C: O(1)
    pub fn parse(sense: &[u8]) -> Option<Self> {
        let response_code = *sense.first()? & 0x7f;
        if response_code & 0x70 != 0x70 { return None; }
        let mut header = Self { response_code, sense_key: 0, asc: 0, ascq: 0, additional_length: 0 };
        if response_code >= 0x72 {
            if let Some(value) = sense.get(1) { header.sense_key = value & 0x0f; }
            if let Some(value) = sense.get(2) { header.asc = *value; }
            if let Some(value) = sense.get(3) { header.ascq = *value; }
            if let Some(value) = sense.get(7) { header.additional_length = *value; }
        } else {
            if let Some(value) = sense.get(2) { header.sense_key = value & 0x0f; }
            let declared_len = sense.get(7).map_or(0, |value| usize::from(*value).saturating_add(8));
            let valid_len = sense.len().min(declared_len);
            if valid_len > 12 { header.asc = sense[12]; }
            if valid_len > 13 { header.ascq = sense[13]; }
        }
        Some(header)
    }

    /// Fixed or descriptor response code without the VALID bit. # C: O(1)
    pub const fn response_code(self) -> u8 { self.response_code }
    /// SCSI sense key. # C: O(1)
    pub const fn sense_key(self) -> u8 { self.sense_key }
    /// Additional sense code. # C: O(1)
    pub const fn asc(self) -> u8 { self.asc }
    /// Additional sense-code qualifier. # C: O(1)
    pub const fn ascq(self) -> u8 { self.ascq }
    /// Descriptor-format additional-sense length; zero for fixed format. # C: O(1)
    pub const fn additional_length(self) -> u8 { self.additional_length }
    /// Whether this describes a deferred error whose command did not run. # C: O(1)
    pub const fn is_deferred(self) -> bool { self.response_code >= 0x70 && self.response_code & 1 != 0 }
}

/// What the block path must do with one completed command. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BlockDisposition {
    /// The command is complete without an error for ordinary block I/O.
    Success,
    /// Reissue the exact command after the supplied process-context delay.
    Retry { delay_ms: u32 },
    /// Return ordinary block I/O failure to the caller.
    Fail,
}

/// Classify a block command completion using the same current-sense rules as
/// Linux's `sd` completion path. `removable` prevents a UNIT ATTENTION from
/// being silently retried as though a changed medium were a transport reset.
/// # C: O(1)
pub fn block_disposition(completion: &CommandCompletion, removable: bool) -> BlockDisposition {
    if completion.host_status() != 0 || completion.driver_status() != 0 && completion.status() != SAM_STAT_CHECK_CONDITION {
        return BlockDisposition::Fail;
    }
    match completion.status() {
        SAM_STAT_GOOD | SAM_STAT_COMMAND_TERMINATED => {
            if completion.resid() == 0 { BlockDisposition::Success } else { BlockDisposition::Fail }
        }
        SAM_STAT_BUSY | SAM_STAT_TASK_SET_FULL | SAM_STAT_TASK_ABORTED => BlockDisposition::Retry { delay_ms: QUEUE_RETRY_DELAY_MS },
        SAM_STAT_CHECK_CONDITION => check_condition_disposition(completion.sense(), completion.resid(), removable),
        _ => BlockDisposition::Fail,
    }
}

fn check_condition_disposition(sense: &[u8], resid: u32, removable: bool) -> BlockDisposition {
    let Some(header) = SenseHeader::parse(sense) else { return BlockDisposition::Fail; };
    if header.is_deferred() { return BlockDisposition::Retry { delay_ms: 0 }; }
    match header.sense_key() {
        NO_SENSE | RECOVERED_ERROR if resid == 0 => BlockDisposition::Success,
        UNIT_ATTENTION if !removable => BlockDisposition::Retry { delay_ms: 0 },
        NOT_READY if header.asc() == 0x04 => match header.ascq() {
            0x01 | 0x04..=0x09 | 0x11 | 0x14 | 0x1a | 0x1b | 0x1d => {
                BlockDisposition::Retry { delay_ms: QUEUE_RETRY_DELAY_MS }
            }
            0x0a => BlockDisposition::Retry { delay_ms: ALUA_TRANSITION_DELAY_MS },
            _ => BlockDisposition::Fail,
        },
        _ => BlockDisposition::Fail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_fixed_sense_honors_the_declared_length() {
        let mut sense = [0u8; 14];
        sense[0] = 0xf0;
        sense[2] = 0x06;
        sense[7] = 4;
        sense[12] = 0x29;
        sense[13] = 0;
        let header = SenseHeader::parse(&sense).expect("fixed sense");
        assert_eq!(header.response_code(), 0x70);
        assert_eq!(header.sense_key(), UNIT_ATTENTION);
        assert_eq!(header.asc(), 0, "bytes beyond declared fixed sense are absent");
        assert_eq!(header.ascq(), 0);
    }

    #[test]
    fn normalize_descriptor_sense_keeps_the_common_header() {
        let header = SenseHeader::parse(&[0x72, 0x02, 0x04, 0x01, 0, 0, 0, 12]).expect("descriptor sense");
        assert_eq!(header.response_code(), 0x72);
        assert_eq!(header.sense_key(), NOT_READY);
        assert_eq!(header.asc(), 0x04);
        assert_eq!(header.ascq(), 0x01);
        assert_eq!(header.additional_length(), 12);
        assert!(!header.is_deferred());
    }

    #[test]
    fn removable_unit_attention_is_not_mistaken_for_a_reset() {
        let completion = CommandCompletion::check_condition(0, &[0x70, 0, UNIT_ATTENTION, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0x28, 0]);
        assert_eq!(block_disposition(&completion, true), BlockDisposition::Fail);
        assert_eq!(block_disposition(&completion, false), BlockDisposition::Retry { delay_ms: 0 });
    }

    #[test]
    fn becoming_ready_waits_but_depopulation_does_not() {
        let ready = CommandCompletion::check_condition(0, &[0x72, NOT_READY, 0x04, 0x01]);
        let depopulating = CommandCompletion::check_condition(0, &[0x72, NOT_READY, 0x04, 0x24]);
        assert_eq!(block_disposition(&ready, false), BlockDisposition::Retry { delay_ms: QUEUE_RETRY_DELAY_MS });
        assert_eq!(block_disposition(&depopulating, false), BlockDisposition::Fail);
    }
}
