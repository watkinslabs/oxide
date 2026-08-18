//! SCSI ATA PASS-THROUGH translation owner.

extern crate alloc;

use alloc::sync::Arc;
use block::{BlockDevice, BlockError, KResult, QueueLimits};
use scsi::{BlockTransport, Command, CommandCompletion, DataDirection, Lun, Transport};

use crate::{Device, Protocol, STATUS_BUSY, STATUS_DF, STATUS_DRQ, STATUS_ERR, Taskfile, TaskfileResult};

const ATA_12: u8 = 0xa1;
const ATA_16: u8 = 0x85;
const VARIABLE_LENGTH_CMD: u8 = 0x7f;
const ATA_32_SERVICE_ACTION: u16 = 0x1ff0;
const EXTEND: u8 = 0x01;
const PROTOCOL_MASK: u8 = 0x1e;
const PROTOCOL_SHIFT: u8 = 1;
const CK_COND: u8 = 0x20;
const T_DIR: u8 = 0x08;
const T_LENGTH_MASK: u8 = 0x03;
const ATA_SET_FEATURES: u8 = 0xef;
const ATA_SET_FEATURES_XFER: u8 = 0x03;
const ATA_TPM_FIRST: u8 = 0x5c;
const ATA_TPM_LAST: u8 = 0x5f;

const CDB12_FEATURE: usize = 3;
const CDB12_NSECT: usize = 4;
const CDB12_LBAL: usize = 5;
const CDB12_LBAM: usize = 6;
const CDB12_LBAH: usize = 7;
const CDB12_DEVICE: usize = 8;
const CDB12_COMMAND: usize = 9;

const CDB16_FEATURE_HI: usize = 3;
const CDB16_FEATURE: usize = 4;
const CDB16_NSECT_HI: usize = 5;
const CDB16_NSECT: usize = 6;
const CDB16_LBAL_HI: usize = 7;
const CDB16_LBAL: usize = 8;
const CDB16_LBAM_HI: usize = 9;
const CDB16_LBAM: usize = 10;
const CDB16_LBAH_HI: usize = 11;
const CDB16_LBAH: usize = 12;
const CDB16_DEVICE: usize = 13;
const CDB16_COMMAND: usize = 14;

const SENSE_DESCRIPTOR: u8 = 0x72;
const SENSE_RECOVERED_ERROR: u8 = 0x01;
const SENSE_ILLEGAL_REQUEST: u8 = 0x05;
const SENSE_ABORTED_COMMAND: u8 = 0x0b;
const SENSE_HARDWARE_ERROR: u8 = 0x04;
const SENSE_MEDIUM_ERROR: u8 = 0x03;
const SENSE_NOT_READY: u8 = 0x02;
const SENSE_UNIT_ATTENTION: u8 = 0x06;
const ASC_INVALID_FIELD_IN_CDB: u8 = 0x24;
const ASC_ATA_INFORMATION: u8 = 0x1d;
const ATA_RETURN_DESCRIPTOR: u8 = 0x09;
const ATA_RETURN_DESCRIPTOR_BYTES: u8 = 12;
const SENSE_ADDITIONAL_BYTES: u8 = 14;

/// SATA translation over the normal shared block transport. Standard SCSI
/// CDBs keep the common implementation; only the ATA pass-through opcodes
/// cross this owner into a taskfile-capable device. # C: O(1)
pub struct SatTransport { base: Arc<BlockTransport>, device: Arc<dyn Device> }

/// Wrap one ATA endpoint for common SCSI disk publication. # C: O(1)
pub fn scsi_transport(inner: Arc<dyn BlockDevice>, device: Arc<dyn Device>) -> Arc<dyn Transport> {
    Arc::new(SatTransport { base: BlockTransport::new(inner), device })
}

impl Transport for SatTransport {
    fn max_lun(&self) -> Lun { self.base.max_lun() }

    fn execute(&self, lun: Lun, command: &Command, data: &mut [u8], direction: DataDirection)
        -> KResult<CommandCompletion>
    {
        self.execute_with_timeout(lun, command, data, direction, 0)
    }

    fn execute_with_timeout(&self, lun: Lun, command: &Command, data: &mut [u8], direction: DataDirection,
                            timeout_ms: u32) -> KResult<CommandCompletion>
    {
        if lun != Lun::ZERO { return Err(BlockError::Enxio); }
        match command.opcode() {
            ATA_12 | ATA_16 | VARIABLE_LENGTH_CMD => self.execute_sat(command.bytes(), data, direction, timeout_ms),
            _ => self.base.execute_with_timeout(lun, command, data, direction, timeout_ms),
        }
    }

    fn sg_io_max_transfer_bytes(&self) -> Option<usize> { Some(self.device.max_transfer_bytes()) }

    fn sg_io_max_cdb_bytes(&self) -> usize { 32 }

    fn queue_limits(&self, block_size: u32) -> KResult<QueueLimits> { self.base.queue_limits(block_size) }
}

impl SatTransport {
    fn execute_sat(&self, cdb: &[u8], data: &mut [u8], direction: DataDirection, timeout_ms: u32)
        -> KResult<CommandCompletion>
    {
        let decoded = match cdb {
            [bytes @ ..] if bytes.len() == 12 && bytes[0] == ATA_12 => decode_ata_12(bytes.try_into().expect("exact ATA12")).map(|taskfile| (taskfile, bytes[2])),
            [bytes @ ..] if bytes.len() == 16 && bytes[0] == ATA_16 => decode_ata_16(bytes.try_into().expect("exact ATA16")).map(|taskfile| (taskfile, bytes[2])),
            [bytes @ ..] if bytes.len() == 32 && bytes[0] == VARIABLE_LENGTH_CMD => decode_ata_32(bytes.try_into().expect("exact ATA32")).map(|taskfile| (taskfile, bytes[11])),
            _ => Err(InvalidField),
        };
        let Ok((taskfile, control)) = decoded else { return Ok(invalid_field(data.len())); };
        if !valid_data_phase(control, taskfile.protocol, direction)
            || taskfile.protocol.uses_ncq() && !self.device.ncq_enabled()
            || blocked_command(taskfile)
        {
            return Ok(invalid_field(data.len()));
        }
        if data.len() > self.device.max_transfer_bytes() { return Err(BlockError::Eio); }
        let result = self.device.execute_taskfile(taskfile, data, timeout_ms)?;
        if result.failed() { return Ok(failed_completion(result, data.len())); }
        if control & CK_COND != 0 { return Ok(check_condition(result)); }
        Ok(CommandCompletion::good())
    }
}

/// SAT CDB field that cannot be represented by the ATA taskfile contract.
/// # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct InvalidField;

/// Translate a complete ATA PASS-THROUGH(12) CDB into its ATA taskfile.
/// # C: O(1)
pub(crate) fn decode_ata_12(cdb: &[u8; 12]) -> Result<Taskfile, InvalidField> {
    if cdb[0] != ATA_12 { return Err(InvalidField); }
    Ok(Taskfile {
        protocol: protocol(cdb[1], cdb[2])?, extend: false,
        feature: cdb[CDB12_FEATURE], nsect: cdb[CDB12_NSECT], lbal: cdb[CDB12_LBAL], lbam: cdb[CDB12_LBAM],
        lbah: cdb[CDB12_LBAH], device: cdb[CDB12_DEVICE], command: cdb[CDB12_COMMAND],
        auxiliary: 0, hob_feature: 0, hob_nsect: 0, hob_lbal: 0, hob_lbam: 0, hob_lbah: 0,
    })
}

/// Translate a complete ATA PASS-THROUGH(16) CDB into its ATA taskfile.
/// # C: O(1)
pub(crate) fn decode_ata_16(cdb: &[u8; 16]) -> Result<Taskfile, InvalidField> {
    if cdb[0] != ATA_16 { return Err(InvalidField); }
    Ok(Taskfile {
        protocol: protocol(cdb[1], cdb[2])?, extend: cdb[1] & EXTEND != 0,
        hob_feature: cdb[CDB16_FEATURE_HI], feature: cdb[CDB16_FEATURE],
        hob_nsect: cdb[CDB16_NSECT_HI], nsect: cdb[CDB16_NSECT],
        hob_lbal: cdb[CDB16_LBAL_HI], lbal: cdb[CDB16_LBAL],
        hob_lbam: cdb[CDB16_LBAM_HI], lbam: cdb[CDB16_LBAM],
        hob_lbah: cdb[CDB16_LBAH_HI], lbah: cdb[CDB16_LBAH],
        device: cdb[CDB16_DEVICE], command: cdb[CDB16_COMMAND],
        auxiliary: 0,
    })
}

/// Translate a complete ATA PASS-THROUGH(32) CDB into its ATA taskfile.
/// # C: O(1)
pub(crate) fn decode_ata_32(cdb: &[u8; 32]) -> Result<Taskfile, InvalidField> {
    if cdb[0] != VARIABLE_LENGTH_CMD || cdb[7] != 24
        || u16::from_be_bytes([cdb[8], cdb[9]]) != ATA_32_SERVICE_ACTION
    {
        return Err(InvalidField);
    }
    Ok(Taskfile {
        protocol: protocol(cdb[10], cdb[11])?, extend: cdb[10] & EXTEND != 0,
        hob_feature: cdb[20], feature: cdb[21], hob_nsect: cdb[22], nsect: cdb[23],
        hob_lbal: cdb[16], lbal: cdb[19], hob_lbam: cdb[15], lbam: cdb[18],
        hob_lbah: cdb[14], lbah: cdb[17], device: cdb[24], command: cdb[25],
        auxiliary: u32::from_be_bytes(cdb[28..32].try_into().expect("fixed ATA32 auxiliary field")),
    })
}

fn protocol(byte1: u8, byte2: u8) -> Result<Protocol, InvalidField> {
    let device_to_host = byte2 & T_DIR != 0;
    match (byte1 & PROTOCOL_MASK) >> PROTOCOL_SHIFT {
        3 => Ok(Protocol::NonData),
        4 => Ok(Protocol::PioIn),
        5 => Ok(Protocol::PioOut),
        6 => Ok(if device_to_host { Protocol::DmaIn } else { Protocol::DmaOut }),
        10 => Ok(Protocol::DmaIn),
        11 => Ok(Protocol::DmaOut),
        12 => Ok(if device_to_host { Protocol::NcqIn } else { Protocol::NcqOut }),
        _ => Err(InvalidField),
    }
}

fn valid_data_phase(cdb2: u8, protocol: Protocol, direction: DataDirection) -> bool {
    if cdb2 & T_LENGTH_MASK == 0 { return direction == DataDirection::None; }
    if direction == DataDirection::None || !protocol.has_data() { return false; }
    protocol.writes() == (direction == DataDirection::ToDevice)
}

fn blocked_command(taskfile: Taskfile) -> bool {
    taskfile.command == ATA_SET_FEATURES && taskfile.feature == ATA_SET_FEATURES_XFER
        || (ATA_TPM_FIRST..=ATA_TPM_LAST).contains(&taskfile.command)
}

fn invalid_field(data_len: usize) -> CommandCompletion {
    CommandCompletion::check_condition(data_len.min(u32::MAX as usize) as u32,
        &[SENSE_DESCRIPTOR, SENSE_ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB, 0, 0, 0, 0, 0])
}

fn check_condition(result: TaskfileResult) -> CommandCompletion {
    CommandCompletion::check_condition(0, &sense(SENSE_RECOVERED_ERROR, 0, ASC_ATA_INFORMATION, result))
}

fn failed_completion(result: TaskfileResult, data_len: usize) -> CommandCompletion {
    let (key, asc, ascq) = sense_error(result.status, result.error);
    CommandCompletion::check_condition(data_len.min(u32::MAX as usize) as u32, &sense(key, asc, ascq, result))
}

fn sense(key: u8, asc: u8, ascq: u8, result: TaskfileResult) -> [u8; 22] {
    let mut sense = [0u8; 22];
    sense[0] = SENSE_DESCRIPTOR;
    sense[1] = key;
    sense[2] = asc;
    sense[3] = ascq;
    sense[7] = SENSE_ADDITIONAL_BYTES;
    sense[8] = ATA_RETURN_DESCRIPTOR;
    sense[9] = ATA_RETURN_DESCRIPTOR_BYTES;
    sense[10] = result.extend as u8;
    sense[11] = result.error;
    sense[12] = result.hob_nsect;
    sense[13] = result.nsect;
    sense[14] = result.hob_lbal;
    sense[15] = result.lbal;
    sense[16] = result.hob_lbam;
    sense[17] = result.lbam;
    sense[18] = result.hob_lbah;
    sense[19] = result.lbah;
    sense[20] = result.device;
    sense[21] = result.status;
    sense
}

fn sense_error(status: u8, error: u8) -> (u8, u8, u8) {
    if status & STATUS_BUSY != 0 { return (SENSE_ABORTED_COMMAND, 0, 0); }
    if status & STATUS_DF != 0 { return (SENSE_HARDWARE_ERROR, 0x44, 0); }
    if error & 0x84 == 0x84 { return (SENSE_ABORTED_COMMAND, 0x47, 0); }
    if error & 0x37 == 0x37 || error & 0x09 == 0x09 || error & 0x08 == 0x08 { return (SENSE_NOT_READY, 0x04, 0); }
    if error & 0x01 != 0 { return (SENSE_MEDIUM_ERROR, 0x13, 0); }
    if error & 0x02 != 0 { return (SENSE_HARDWARE_ERROR, 0, 0); }
    if error & 0x10 != 0 { return (SENSE_ILLEGAL_REQUEST, 0x21, 0); }
    if error & 0x20 != 0 { return (SENSE_UNIT_ATTENTION, 0x28, 0); }
    if error & 0xc0 != 0 { return (SENSE_MEDIUM_ERROR, 0x11, 0x04); }
    if status & STATUS_ERR != 0 || status & STATUS_DRQ != 0 { return (SENSE_ABORTED_COMMAND, 0, 0); }
    (SENSE_ABORTED_COMMAND, 0, 0)
}
