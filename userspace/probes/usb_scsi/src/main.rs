//! Live USB Bulk-Only/SCSI acceptance against the QEMU USB disk.

use core::ffi::c_void;
use support::{fail, line, report, Verdict};

const PROBE: &str = "usb_scsi_probe";
const SG_IO: libc::c_ulong = 0x2285;
const SG_DXFER_FROM_DEV: libc::c_int = -3;
const INQUIRY: u8 = 0x12;
const READ_CAPACITY_10: u8 = 0x25;
const USB_VENDOR: &str = "QEMU";
const USB_PRODUCT_PREFIX: &str = "QEMU HARD";
const USB_SERIAL: &str = "oxide-usb0";
// The serial debug shell is available before the xHCI root-hub worker has
// necessarily enumerated its downstream disk.  Discover the devtmpfs node by
// its SCSI identity, with one bounded deadline, rather than assuming a boot
// timestamp or ordering this check behind unrelated userspace services.
const DISCOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const DISCOVERY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

#[repr(C)]
struct SgIoHdr {
    interface_id: libc::c_int,
    dxfer_direction: libc::c_int,
    cmd_len: u8,
    mx_sb_len: u8,
    iovec_count: u16,
    dxfer_len: u32,
    dxferp: *mut c_void,
    cmdp: *mut u8,
    sbp: *mut u8,
    timeout: u32,
    flags: u32,
    pack_id: libc::c_int,
    usr_ptr: *mut c_void,
    status: u8,
    masked_status: u8,
    msg_status: u8,
    sb_len_wr: u8,
    host_status: u16,
    driver_status: u16,
    resid: libc::c_int,
    duration: u32,
    info: u32,
}

const _: [(); 88] = [(); core::mem::size_of::<SgIoHdr>()];

fn main() -> std::process::ExitCode { report(PROBE, run()) }

fn run() -> Verdict {
    let deadline = std::time::Instant::now() + DISCOVERY_TIMEOUT;
    loop {
        if let Some(verdict) = inspect_all_disks() { return verdict; }
        if std::time::Instant::now() >= deadline { return fail("usb-scsi-disk-not-identified"); }
        std::thread::sleep(DISCOVERY_POLL_INTERVAL);
    }
}

/// Inspect every devtmpfs SCSI disk that exists at this instant.  A missing
/// node is expected while xHCI asynchronously enumerates the device.
fn inspect_all_disks() -> Option<Verdict> {
    for suffix in b'a'..=b'z' {
        let path = format!("/dev/sd{}", suffix as char);
        // The xHCI transport publishes the USB descriptor serial through the
        // standard block-device identity kobject. Filter on that non-blocking
        // value first: an unrelated disk's SG_IO can itself wait for I/O,
        // which would prevent the bounded discovery loop from reaching USB.
        if sysfs_scsi_serial(&path).as_deref() != Some(USB_SERIAL) { continue; }
        let c_path = match std::ffi::CString::new(path.as_str()) { Ok(path) => path, Err(_) => continue };
        // SAFETY: the C path is NUL-terminated and lives for the open call.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
        if fd < 0 { continue; }
        let verdict = inspect(&path, fd);
        // SAFETY: `fd` was returned by open and is closed exactly once here.
        unsafe { libc::close(fd) };
        if let Some(verdict) = verdict { return Some(verdict); }
    }
    None
}

/// Read the published USB descriptor serial without issuing disk I/O. # C: O(1)
fn sysfs_scsi_serial(path: &str) -> Option<String> {
    let disk = path.strip_prefix("/dev/")?;
    let serial = std::fs::read_to_string(format!("/sys/class/block/{disk}/device/serial")).ok()?;
    Some(serial.trim().to_owned())
}

fn inspect(path: &str, fd: libc::c_int) -> Option<Verdict> {
    let (vendor, product) = match standard_inquiry(fd) {
        Ok(identity) => identity,
        Err(reason) => {
            line(&format!("{PROBE}: inquiry {reason}"));
            return Some(fail("usb-scsi-inquiry-failed"));
        }
    };
    if !is_qemu_usb_disk(&vendor, &product) {
        line(&format!("{PROBE}: path={path} vendor={vendor} product={product}"));
        return Some(fail("usb-scsi-inquiry-identity-mismatch"));
    }
    let (blocks, block_size) = match read_capacity_10(fd) {
        Ok(capacity) => capacity,
        Err(reason) => {
            line(&format!("{PROBE}: capacity {reason}"));
            return Some(fail("usb-scsi-capacity-command-failed"));
        }
    };
    if block_size != 512 || blocks == 0 {
        return Some(fail("usb-scsi-capacity-invalid"));
    }
    line(&format!("{PROBE}: path={path} vendor={vendor} product={product} blocks={blocks} block-size={block_size}"));
    Some(Verdict::Pass(format!("path={path} vendor={vendor} product={product}")))
}

fn standard_inquiry(fd: libc::c_int) -> Result<(String, String), &'static str> {
    let mut cdb = [INQUIRY, 0, 0, 0, 36, 0];
    let mut data = [0u8; 36];
    sg_io(fd, &mut cdb, &mut data)?;
    if data[0] & 0x1f != 0 { return Err("inquiry-not-direct-access"); }
    Ok((scsi_text(&data[8..16])?, scsi_text(&data[16..32])?))
}

fn scsi_text(bytes: &[u8]) -> Result<String, &'static str> {
    let value = core::str::from_utf8(bytes).map_err(|_| "inquiry-text-not-utf8")?;
    Ok(value.trim_matches([' ', '\0']).to_string())
}

fn is_qemu_usb_disk(vendor: &str, product: &str) -> bool {
    vendor == USB_VENDOR && product.starts_with(USB_PRODUCT_PREFIX)
}

fn read_capacity_10(fd: libc::c_int) -> Result<(u64, u32), &'static str> {
    let mut cdb = [READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut data = [0u8; 8];
    sg_io(fd, &mut cdb, &mut data)?;
    let last_lba = u32::from_be_bytes(data[..4].try_into().expect("fixed capacity bytes"));
    let block_size = u32::from_be_bytes(data[4..].try_into().expect("fixed capacity bytes"));
    Ok((u64::from(last_lba) + 1, block_size))
}

fn sg_io(fd: libc::c_int, cdb: &mut [u8], data: &mut [u8]) -> Result<(), &'static str> {
    let mut sense = [0u8; 32];
    let mut hdr = SgIoHdr {
        interface_id: b'S' as libc::c_int,
        dxfer_direction: SG_DXFER_FROM_DEV,
        cmd_len: cdb.len() as u8,
        mx_sb_len: sense.len() as u8,
        iovec_count: 0,
        dxfer_len: data.len() as u32,
        dxferp: data.as_mut_ptr().cast(),
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
    // SAFETY: every pointer in the SG header targets a live, exact-size local
    // object for this synchronous ioctl; the kernel retains none after return.
    if unsafe { libc::ioctl(fd, SG_IO, &mut hdr) } != 0 { return Err("sg-io-errno"); }
    if hdr.status != 0 || hdr.host_status != 0 || hdr.driver_status != 0 || hdr.resid != 0 {
        return Err("sg-io-command-failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_qemu_usb_disk, scsi_text};

    #[test]
    fn qemu_usb_inquiry_identity_is_distinct_from_an_ata_qemu_disk() {
        assert_eq!(scsi_text(b"QEMU    ").as_deref(), Ok("QEMU"));
        assert!(is_qemu_usb_disk("QEMU", "QEMU HARDDISK"));
        assert!(!is_qemu_usb_disk("ATA", "QEMU HARDDISK"));
    }
}
