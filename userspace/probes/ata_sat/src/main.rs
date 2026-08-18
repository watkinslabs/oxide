//! Live SG_IO ATA PASS-THROUGH(16)/(32) IDENTIFY transactions against QEMU AHCI.

use core::ffi::c_void;
use support::{fail, line, report, Verdict};

const PROBE: &str = "ata_sat_probe";
const HDIO_GET_IDENTITY: libc::c_ulong = 0x030d;
const HDIO_DRIVE_TASK: libc::c_ulong = 0x031e;
const HDIO_DRIVE_CMD: libc::c_ulong = 0x031f;
const SG_IO: libc::c_ulong = 0x2285;
const SG_DXFER_FROM_DEV: libc::c_int = -3;
const ATA_PASS_THROUGH_16: u8 = 0x85;
const VARIABLE_LENGTH_CMD: u8 = 0x7f;
const ATA_PASS_THROUGH_32: u16 = 0x1ff0;
const ATA_IDENTIFY_DEVICE: u8 = 0xec;
const ATA_CHECK_POWER_MODE: u8 = 0xe5;
const IDENTIFY_BYTES: usize = 512;
const SENSE_BYTES: usize = 32;
const SERIAL_OFFSET: usize = 20;

#[repr(C)]
struct SgIoHdr {
    interface_id:     libc::c_int,
    dxfer_direction:  libc::c_int,
    cmd_len:          u8,
    mx_sb_len:        u8,
    iovec_count:      u16,
    dxfer_len:        u32,
    dxferp:           *mut c_void,
    cmdp:             *mut u8,
    sbp:              *mut u8,
    timeout:          u32,
    flags:            u32,
    pack_id:          libc::c_int,
    usr_ptr:          *mut c_void,
    status:           u8,
    masked_status:    u8,
    msg_status:       u8,
    sb_len_wr:        u8,
    host_status:      u16,
    driver_status:    u16,
    resid:            libc::c_int,
    duration:         u32,
    info:             u32,
}

const _: [(); 88] = [(); core::mem::size_of::<SgIoHdr>()];

fn main() -> std::process::ExitCode { report(PROBE, run()) }

fn run() -> Verdict {
    for suffix in b'a'..=b'z' {
        let path = format!("/dev/sd{}", suffix as char);
        let c_path = std::ffi::CString::new(path.as_str()).expect("node path");
        // SAFETY: `c_path` remains valid for the call and the descriptor is
        // closed once along each path below.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        if fd < 0 { continue; }
        let mut identity = [0u8; IDENTIFY_BYTES];
        // SAFETY: the output page is exactly the documented HDIO object.
        let identity_result = unsafe { libc::ioctl(fd, HDIO_GET_IDENTITY, identity.as_mut_ptr()) };
        if identity_result != 0 {
            // SAFETY: `fd` came from open and this path closes it once.
            unsafe { libc::close(fd); }
            continue;
        }
        let verdict = execute_identify(fd, &path);
        // SAFETY: `fd` came from open and this path closes it once.
        unsafe { libc::close(fd); }
        return verdict;
    }
    fail("no-ahci-sd-node-answered-hdio-get-identity")
}

fn execute_identify(fd: libc::c_int, path: &str) -> Verdict {
    let mut cdb16 = [0u8; 16];
    cdb16[0] = ATA_PASS_THROUGH_16;
    cdb16[1] = 0x08;
    cdb16[2] = 0x2e;
    cdb16[14] = ATA_IDENTIFY_DEVICE;
    let (serial, status, ata_status) = match sg_identify(fd, &mut cdb16) {
        Ok(result) => result,
        Err(reason) => return fail(reason.as_str()),
    };

    let mut cdb32 = [0u8; 32];
    cdb32[0] = VARIABLE_LENGTH_CMD;
    cdb32[7] = 24;
    cdb32[8..10].copy_from_slice(&ATA_PASS_THROUGH_32.to_be_bytes());
    cdb32[10] = 0x08;
    cdb32[11] = 0x2e;
    cdb32[25] = ATA_IDENTIFY_DEVICE;
    let (serial32, _, _) = match sg_identify(fd, &mut cdb32) {
        Ok(result) => result,
        Err(reason) => return fail(reason.as_str()),
    };
    if serial32 != serial { return fail("ata32-identify-data-was-not-returned"); }
    if let Err(reason) = legacy_hdio(fd) { return fail(reason); }
    line(&format!("{PROBE}: path={path} serial={serial} status={status:#04x} ata-status={ata_status:#04x}"));
    Verdict::Pass(format!("path={path} serial={serial}"))
}

fn sg_identify(fd: libc::c_int, cdb: &mut [u8]) -> Result<(String, u8, u8), String> {
    let mut page = [0u8; IDENTIFY_BYTES];
    let mut sense = [0u8; SENSE_BYTES];
    let mut hdr = SgIoHdr {
        interface_id: b'S' as libc::c_int,
        dxfer_direction: SG_DXFER_FROM_DEV,
        cmd_len: cdb.len() as u8,
        mx_sb_len: sense.len() as u8,
        iovec_count: 0,
        dxfer_len: page.len() as u32,
        dxferp: page.as_mut_ptr().cast(),
        cmdp: cdb.as_mut_ptr(),
        sbp: sense.as_mut_ptr(),
        timeout: 7_000,
        flags: 0,
        pack_id: 0,
        usr_ptr: core::ptr::null_mut(),
        status: 0,
        masked_status: 0,
        msg_status: 0,
        sb_len_wr: 0,
        host_status: 0,
        driver_status: 0,
        resid: 0,
        duration: 0,
        info: 0,
    };
    // SAFETY: `hdr` contains valid pointers to its live CDB, sense, and data
    // objects, each retained until the kernel completes the synchronous ioctl.
    let result = unsafe { libc::ioctl(fd, SG_IO, &mut hdr) };
    if result != 0 { return Err(format!("sg-io-errno={}", support::errno())); }
    if hdr.status != 0x02 || hdr.resid != 0 { return Err("ck-cond-or-full-transfer-missing".into()); }
    if hdr.sb_len_wr < 22 || sense[0] != 0x72 || sense[1] != 0x01 || sense[2] != 0 || sense[3] != 0x1d
        || sense[8] != 0x09 || sense[9] != 0x0c
    {
        return Err("ata-return-descriptor-missing".into());
    }
    let serial = ata_string(&page, SERIAL_OFFSET, 20);
    if serial != "oxahci0" { return Err("ata-identify-data-was-not-returned".into()); }
    Ok((serial, hdr.status, sense[21]))
}

fn legacy_hdio(fd: libc::c_int) -> Result<(), &'static str> {
    let mut command = [0u8; IDENTIFY_BYTES + 4];
    command[0] = ATA_IDENTIFY_DEVICE;
    command[3] = 1;
    // SAFETY: the header plus one legacy ATA sector remains live for the
    // synchronous command and the kernel owns no pointer after it returns.
    if unsafe { libc::ioctl(fd, HDIO_DRIVE_CMD, command.as_mut_ptr()) } != 0 { return Err("hdio-drive-cmd-failed"); }
    if ata_string(command[4..].try_into().expect("one identity page"), SERIAL_OFFSET, 20) != "oxahci0" {
        return Err("hdio-drive-cmd-data-missing");
    }
    let mut task = [0u8; 7];
    task[0] = ATA_CHECK_POWER_MODE;
    // SAFETY: the exact seven-byte Linux HDIO taskfile object remains live
    // through this synchronous ioctl and is copied back in place.
    if unsafe { libc::ioctl(fd, HDIO_DRIVE_TASK, task.as_mut_ptr()) } != 0 { return Err("hdio-drive-task-failed"); }
    Ok(())
}

fn ata_string(page: &[u8; IDENTIFY_BYTES], offset: usize, bytes: usize) -> String {
    let mut field = page[offset..offset + bytes].to_vec();
    for word in field.chunks_exact_mut(2) { word.swap(0, 1); }
    let first = field.iter().position(|byte| !matches!(*byte, b' ' | 0)).unwrap_or(bytes);
    let last = field.iter().rposition(|byte| !matches!(*byte, b' ' | 0)).map_or(first, |index| index + 1);
    String::from_utf8_lossy(&field[first..last]).into_owned()
}
