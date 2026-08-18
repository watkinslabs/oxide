//! USB mass-storage Bulk-Only Transport and SCSI command wire contracts.

/// USB Mass Storage class code. # C: O(1)
pub const USB_CLASS_MASS_STORAGE: u8 = 8;
/// Transparent SCSI command-set subclass. # C: O(1)
pub const USB_SUBCLASS_SCSI: u8 = 6;
/// Bulk-Only Transport interface protocol. # C: O(1)
pub const USB_PROTOCOL_BULK_ONLY: u8 = 0x50;
/// Largest Bulk-Only Transport LUN encoded in the command wrapper. # C: O(1)
pub const USB_BULK_MAX_LUN: u8 = 0x0f;
/// Bulk command block wrapper byte length. # C: O(1)
pub const CBW_BYTES: usize = 31;
/// Bulk command status wrapper byte length. # C: O(1)
pub const CSW_BYTES: usize = 13;
/// Bulk command block wrapper little-endian signature. # C: O(1)
pub const CBW_SIGNATURE: u32 = 0x4342_5355;
/// Bulk command status wrapper little-endian signature. # C: O(1)
pub const CSW_SIGNATURE: u32 = 0x5342_5355;
/// Data direction bit for a device-to-host command. # C: O(1)
pub const CBW_FLAG_IN: u8 = 0x80;
/// Command completed successfully. # C: O(1)
pub const CSW_STATUS_PASSED: u8 = 0;
/// Command failed at the SCSI layer. # C: O(1)
pub const CSW_STATUS_FAILED: u8 = 1;
/// Host and device disagreed about a transfer phase. # C: O(1)
pub const CSW_STATUS_PHASE: u8 = 2;

/// One configured mass-storage interface with its two required bulk endpoints. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MassStorageInterface {
    pub configuration: u8,
    pub interface: u8,
    pub bulk_in: u8,
    pub bulk_in_packet: u16,
    pub bulk_out: u8,
    pub bulk_out_packet: u16,
}

/// Validated device status wrapper result. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CswStatus { Passed, Failed, PhaseError }

/// Build a strict 31-byte Bulk-Only command wrapper. # C: O(1)
pub fn command_block(tag: u32, transfer_bytes: u32, device_to_host: bool, lun: u8, cdb: &[u8]) -> Option<[u8; CBW_BYTES]> {
    if lun > USB_BULK_MAX_LUN || cdb.is_empty() || cdb.len() > 16 { return None; }
    let mut cbw = [0u8; CBW_BYTES];
    cbw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
    cbw[4..8].copy_from_slice(&tag.to_le_bytes());
    cbw[8..12].copy_from_slice(&transfer_bytes.to_le_bytes());
    cbw[12] = if device_to_host { CBW_FLAG_IN } else { 0 };
    cbw[13] = lun;
    cbw[14] = cdb.len() as u8;
    cbw[15..15 + cdb.len()].copy_from_slice(cdb);
    Some(cbw)
}

/// Validate a Bulk-Only status wrapper for its command tag and transfer size. # C: O(1)
pub fn command_status(bytes: &[u8], tag: u32, transfer_bytes: u32) -> Option<(CswStatus, u32)> {
    if bytes.len() != CSW_BYTES || u32::from_le_bytes(bytes[0..4].try_into().ok()?) != CSW_SIGNATURE { return None; }
    if u32::from_le_bytes(bytes[4..8].try_into().ok()?) != tag { return None; }
    let residue = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    if residue > transfer_bytes { return None; }
    let status = match bytes[12] {
        CSW_STATUS_PASSED => CswStatus::Passed,
        CSW_STATUS_FAILED => CswStatus::Failed,
        CSW_STATUS_PHASE => CswStatus::PhaseError,
        _ => return None,
    };
    Some((status, residue))
}

/// Build SCSI READ(10) for a nonzero logical-block count. # C: O(1)
pub fn read10_cdb(lba: u32, blocks: u16) -> Option<[u8; 10]> { rw10_cdb(0x28, lba, blocks) }

/// Build SCSI WRITE(10) for a nonzero logical-block count. # C: O(1)
pub fn write10_cdb(lba: u32, blocks: u16) -> Option<[u8; 10]> { rw10_cdb(0x2a, lba, blocks) }

fn rw10_cdb(opcode: u8, lba: u32, blocks: u16) -> Option<[u8; 10]> {
    if blocks == 0 { return None; }
    let mut cdb = [0u8; 10];
    cdb[0] = opcode;
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
    Some(cdb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_block_uses_bulk_only_wire_order() {
        let cbw = command_block(0x1020_3040, 512, true, 0, &read10_cdb(7, 1).unwrap()).unwrap();
        assert_eq!(&cbw[..15], &[0x55, 0x53, 0x42, 0x43, 0x40, 0x30, 0x20, 0x10, 0, 2, 0, 0, 0x80, 0, 10]);
        assert_eq!(&cbw[15..25], &[0x28, 0, 0, 0, 0, 7, 0, 0, 1, 0]);
        assert!(command_block(1, 0, false, 16, &[0]).is_none());
        assert!(command_block(1, 0, false, 0, &[]).is_none());
    }

    #[test]
    fn command_status_rejects_wrong_signature_tag_and_residue() {
        let mut csw = [0u8; CSW_BYTES];
        csw[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        csw[4..8].copy_from_slice(&9u32.to_le_bytes());
        csw[8..12].copy_from_slice(&12u32.to_le_bytes());
        assert_eq!(command_status(&csw, 9, 512), Some((CswStatus::Passed, 12)));
        assert!(command_status(&csw, 8, 512).is_none());
        assert!(command_status(&csw, 9, 11).is_none());
        csw[0] = 0;
        assert!(command_status(&csw, 9, 512).is_none());
    }

    #[test]
    fn bulk_command_builder_keeps_lun_and_cdb_wire_order() {
        assert_eq!(read10_cdb(0x1122_3344, 0x5566).unwrap(), [0x28, 0, 0x11, 0x22, 0x33, 0x44, 0, 0x55, 0x66, 0]);
        assert!(write10_cdb(0, 0).is_none());
        assert!(command_block(1, 0, false, USB_BULK_MAX_LUN, &[0]).is_some());
        assert!(command_block(1, 0, false, USB_BULK_MAX_LUN + 1, &[0]).is_none());
    }
}
