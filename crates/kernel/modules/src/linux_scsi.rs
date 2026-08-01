use core::ffi::c_char;
use core::ptr::null;

const SCSI_SENSE_BUFFERSIZE: usize = 96;
const SCSI_FIXED_SENSE_LEN: usize = 18;
const SCSI_DESC_SENSE_LEN: usize = 8;
const SCSI_INFO_DESC_LEN: usize = 12;

const SCSI_SENSE_CURRENT: u8 = 0x70;
const SCSI_SENSE_DESC_CURRENT: u8 = 0x72;
const SCSI_SENSE_VALID: u8 = 0x80;
const SCSI_SENSE_ADDITIONAL_LEN_OFF: usize = 7;
const SCSI_SENSE_ASC_OFF: usize = 12;
const SCSI_SENSE_ASCQ_OFF: usize = 13;
const SCSI_DESC_INFO: u8 = 0x00;

#[repr(C)]
pub struct ScsiLun {
    scsi_lun: [u8; 8],
}

#[unsafe(no_mangle)]
pub static scsi_command_size_tbl: [u8; 8] = [6, 10, 10, 12, 16, 12, 10, 10];

static DEV_DIRECT: &[u8] = b"Direct-Access\0";
static DEV_SEQUENTIAL: &[u8] = b"Sequential-Access\0";
static DEV_PRINTER: &[u8] = b"Printer\0";
static DEV_PROCESSOR: &[u8] = b"Processor\0";
static DEV_WORM: &[u8] = b"WORM\0";
static DEV_CD_DVD: &[u8] = b"CD/DVD\0";
static DEV_SCANNER: &[u8] = b"Scanner\0";
static DEV_OPTICAL: &[u8] = b"Optical Device\0";
static DEV_MEDIUM_CHANGER: &[u8] = b"Medium Changer\0";
static DEV_COMM: &[u8] = b"Communications\0";
static DEV_RAID: &[u8] = b"RAID\0";
static DEV_ENCLOSURE: &[u8] = b"Enclosure\0";
static DEV_RBC: &[u8] = b"RBC\0";
static DEV_OCRW: &[u8] = b"Optical Card Reader/Writer\0";
static DEV_BRIDGE: &[u8] = b"Bridge Controller\0";
static DEV_OSD: &[u8] = b"Object Storage\0";
static DEV_ADC: &[u8] = b"Automation/Drive Interface\0";
static DEV_ZBC: &[u8] = b"Zoned Block\0";
static DEV_UNKNOWN: &[u8] = b"Unknown\0";

#[repr(transparent)]
pub struct ScsiDeviceTypeTable([*const c_char; 32]);

unsafe impl Sync for ScsiDeviceTypeTable {}

#[unsafe(no_mangle)]
pub static scsi_device_type: ScsiDeviceTypeTable = ScsiDeviceTypeTable([
    DEV_DIRECT.as_ptr() as *const c_char,
    DEV_SEQUENTIAL.as_ptr() as *const c_char,
    DEV_PRINTER.as_ptr() as *const c_char,
    DEV_PROCESSOR.as_ptr() as *const c_char,
    DEV_WORM.as_ptr() as *const c_char,
    DEV_CD_DVD.as_ptr() as *const c_char,
    DEV_SCANNER.as_ptr() as *const c_char,
    DEV_OPTICAL.as_ptr() as *const c_char,
    DEV_MEDIUM_CHANGER.as_ptr() as *const c_char,
    DEV_COMM.as_ptr() as *const c_char,
    null(), null(),
    DEV_RAID.as_ptr() as *const c_char,
    DEV_ENCLOSURE.as_ptr() as *const c_char,
    DEV_RBC.as_ptr() as *const c_char,
    DEV_OCRW.as_ptr() as *const c_char,
    DEV_BRIDGE.as_ptr() as *const c_char,
    DEV_OSD.as_ptr() as *const c_char,
    DEV_ADC.as_ptr() as *const c_char,
    DEV_ZBC.as_ptr() as *const c_char,
    DEV_UNKNOWN.as_ptr() as *const c_char,
    DEV_UNKNOWN.as_ptr() as *const c_char,
    DEV_UNKNOWN.as_ptr() as *const c_char,
    DEV_UNKNOWN.as_ptr() as *const c_char,
    DEV_UNKNOWN.as_ptr() as *const c_char,
    DEV_UNKNOWN.as_ptr() as *const c_char,
    DEV_UNKNOWN.as_ptr() as *const c_char,
    DEV_UNKNOWN.as_ptr() as *const c_char,
    DEV_UNKNOWN.as_ptr() as *const c_char,
    DEV_UNKNOWN.as_ptr() as *const c_char,
    DEV_UNKNOWN.as_ptr() as *const c_char,
    DEV_UNKNOWN.as_ptr() as *const c_char,
]);

/// Register Linux SCSI target helper KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("int_to_scsilun",              int_to_scsilun              as *const () as usize),
        ("scsi_build_sense_buffer",    scsi_build_sense_buffer    as *const () as usize),
        ("scsi_set_sense_information", scsi_set_sense_information as *const () as usize),
    ] { export(name, addr, false); }
    export("scsi_command_size_tbl", scsi_command_size_tbl.as_ptr() as usize, false);
    export("scsi_device_type", scsi_device_type.0.as_ptr() as usize, false);
}

unsafe extern "C" fn int_to_scsilun(lun: u64, out: *mut ScsiLun) {
    if out.is_null() { return; }
    // SAFETY: out was null-checked and int_to_scsilun's KPI contract is a caller-owned struct scsi_lun, whose whole 8-byte array is this one field; the borrow ends before return.
    let dst = unsafe { &mut (*out).scsi_lun };
    *dst = [0; 8];
    if lun <= 0x00ff {
        dst[1] = lun as u8;
    } else if lun <= 0x3fff {
        dst[0] = 0x40 | ((lun >> 8) as u8 & 0x3f);
        dst[1] = lun as u8;
    } else {
        dst[0] = 0xc0 | ((lun >> 16) as u8 & 0x3f);
        dst[1] = (lun >> 8) as u8;
        dst[2] = lun as u8;
    }
}

unsafe extern "C" fn scsi_build_sense_buffer(desc: i32, buf: *mut u8, key: u8, asc: u8, ascq: u8) -> bool {
    if buf.is_null() { return false; }
    // SAFETY: buf was null-checked and scsi_build_sense_buffer's KPI contract is a sense buffer of exactly SCSI_SENSE_BUFFERSIZE bytes (the size Linux
    // callers declare as cmd->sense_buffer), so zeroing that many bytes stays in bounds.
    unsafe { core::ptr::write_bytes(buf, 0, SCSI_SENSE_BUFFERSIZE); }
    if desc != 0 {
        // SAFETY: same SCSI_SENSE_BUFFERSIZE-byte buffer just zeroed; the descriptor header touches offsets 0..3, far inside 96.
        unsafe {
            *buf.add(0) = SCSI_SENSE_DESC_CURRENT;
            *buf.add(1) = key;
            *buf.add(2) = asc;
            *buf.add(3) = ascq;
        }
    } else {
        // SAFETY: same SCSI_SENSE_BUFFERSIZE-byte buffer just zeroed; the highest offset written here is SCSI_SENSE_ASCQ_OFF (13) < 96.
        unsafe {
            *buf.add(0) = SCSI_SENSE_CURRENT;
            *buf.add(2) = key;
            *buf.add(SCSI_SENSE_ADDITIONAL_LEN_OFF) = (SCSI_FIXED_SENSE_LEN - 8) as u8;
            *buf.add(SCSI_SENSE_ASC_OFF) = asc;
            *buf.add(SCSI_SENSE_ASCQ_OFF) = ascq;
        }
    }
    true
}

unsafe extern "C" fn scsi_set_sense_information(buf: *mut u8, len: i32, info: u64) {
    if buf.is_null() || len <= 0 { return; }
    let len = len as usize;
    // SAFETY: buf was null-checked and len > 0 was rejected above, so scsi_set_sense_information's contract gives at least one readable byte, which is the response code.
    let code = unsafe { *buf & 0x7f };
    if (code == 0x70 || code == 0x71) && len >= SCSI_FIXED_SENSE_LEN {
        // SAFETY: the branch condition proved len >= SCSI_FIXED_SENSE_LEN (18) readable/writable bytes, and the fixed-format INFORMATION field spans offsets 0..6.
        unsafe {
            *buf.add(0) |= SCSI_SENSE_VALID;
            *buf.add(3) = (info >> 24) as u8;
            *buf.add(4) = (info >> 16) as u8;
            *buf.add(5) = (info >> 8) as u8;
            *buf.add(6) = info as u8;
        }
    } else if (code == 0x72 || code == 0x73) && len >= SCSI_DESC_SENSE_LEN + SCSI_INFO_DESC_LEN {
        let off = SCSI_DESC_SENSE_LEN;
        // SAFETY: the branch condition proved len >= SCSI_DESC_SENSE_LEN + SCSI_INFO_DESC_LEN (20) bytes; the information descriptor occupies off..off+11 = 8..19
        // and the additional-length byte at SCSI_SENSE_ADDITIONAL_LEN_OFF (7) is below off, so every access is inside those 20 bytes.
        unsafe {
            *buf.add(off) = SCSI_DESC_INFO;
            *buf.add(off + 1) = 0x0a;
            *buf.add(off + 2) = SCSI_SENSE_VALID;
            *buf.add(off + 4) = (info >> 56) as u8;
            *buf.add(off + 5) = (info >> 48) as u8;
            *buf.add(off + 6) = (info >> 40) as u8;
            *buf.add(off + 7) = (info >> 32) as u8;
            *buf.add(off + 8) = (info >> 24) as u8;
            *buf.add(off + 9) = (info >> 16) as u8;
            *buf.add(off + 10) = (info >> 8) as u8;
            *buf.add(off + 11) = info as u8;
            let add_len = (*buf.add(SCSI_SENSE_ADDITIONAL_LEN_OFF)).max(SCSI_INFO_DESC_LEN as u8);
            *buf.add(SCSI_SENSE_ADDITIONAL_LEN_OFF) = add_len;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lun_encoding_covers_peripheral_and_flat_forms() {
        let _modules = crate::test_serial::claim();
        let mut lun = ScsiLun { scsi_lun: [0xff; 8] };
        // SAFETY: int_to_scsilun's precondition is a writable struct scsi_lun; lun is a live local of exactly that type, uniquely borrowed here.
        unsafe { int_to_scsilun(7, &mut lun); }
        assert_eq!(lun.scsi_lun, [0, 7, 0, 0, 0, 0, 0, 0]);
        // SAFETY: same live local ScsiLun, still uniquely borrowed and fully overwritten by the call, so the flat-form encoding stays in its 8 bytes.
        unsafe { int_to_scsilun(0x1234, &mut lun); }
        assert_eq!(lun.scsi_lun[0], 0x52);
        assert_eq!(lun.scsi_lun[1], 0x34);
    }

    #[test]
    fn sense_helpers_build_fixed_and_descriptor_buffers() {
        let _modules = crate::test_serial::claim();
        let mut fixed = [0u8; SCSI_SENSE_BUFFERSIZE];
        // SAFETY: scsi_build_sense_buffer requires SCSI_SENSE_BUFFERSIZE writable bytes, and `fixed` is a local array declared with exactly that length.
        assert!(unsafe { scsi_build_sense_buffer(0, fixed.as_mut_ptr(), 5, 0x20, 0) });
        assert_eq!(fixed[0], SCSI_SENSE_CURRENT);
        assert_eq!(fixed[2], 5);
        assert_eq!(fixed[12], 0x20);
        // SAFETY: the length argument is `fixed.len()` itself, so the len bound the callee checks against is exactly the local array's real size.
        unsafe { scsi_set_sense_information(fixed.as_mut_ptr(), fixed.len() as i32, 0x0102_0304); }
        assert_eq!(&fixed[3..7], &[1, 2, 3, 4]);

        let mut desc = [0u8; SCSI_SENSE_BUFFERSIZE];
        // SAFETY: `desc` is likewise a local array of SCSI_SENSE_BUFFERSIZE bytes, which is the buffer size scsi_build_sense_buffer zeroes.
        assert!(unsafe { scsi_build_sense_buffer(1, desc.as_mut_ptr(), 2, 0x3a, 0) });
        // SAFETY: the length passed is `desc.len()`, so the descriptor-format bound (>= 20 bytes) is checked against the local array's real 96-byte size.
        unsafe { scsi_set_sense_information(desc.as_mut_ptr(), desc.len() as i32, 0x0102_0304_0506_0708); }
        assert_eq!(&desc[8..12], &[SCSI_DESC_INFO, 0x0a, SCSI_SENSE_VALID, 0]);
        assert_eq!(&desc[12..20], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn exported_tables_match_group_command_sizes() {
        let _modules = crate::test_serial::claim();
        assert_eq!(scsi_command_size_tbl, [6, 10, 10, 12, 16, 12, 10, 10]);
        assert!(!scsi_device_type.0[0].is_null());
    }
}
