// Linux firmware-loader KPI facade.
//
// Owned responsibilities:
// - C ABI structs and exported request/release entry points.
// - Linux firmware search-path construction.
// - Rootfs-backed lookup handoff for synchronous firmware requests.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{c_char, c_void};
use core::ptr::null;
use sync::{Modules as ModulesLockClass, Spinlock};

const LINUX_OK: i32 = 0;
const LINUX_EINVAL: i32 = 22;
const LINUX_ENOENT: i32 = 2;
const LINUX_ENOMEM: i32 = 12;

const PATH_MAX: usize = 4096;
const FW_NAME_MAX: usize = 255;
const CSTR_SCAN_MAX: usize = PATH_MAX;
const FW_PREFIXES: [&[u8]; 3] = [b"/lib/firmware/updates/", b"/lib/firmware/", b"/usr/lib/firmware/"];

type FirmwareReader = fn(&[u8]) -> Option<Vec<u8>>;

#[repr(C)]
pub struct LinuxFirmware {
    pub size: usize,
    pub data: *const u8,
    pub pages: *mut *mut c_void,
    pub priv_data: *mut c_void,
}

#[repr(C)]
struct FirmwareAllocation {
    fw: LinuxFirmware,
    bytes: Vec<u8>,
}

static READER: Spinlock<Option<FirmwareReader>, ModulesLockClass> = Spinlock::new(None);

/// Register Linux firmware KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("request_firmware",        request_firmware        as *const () as usize),
        ("request_firmware_direct", request_firmware_direct as *const () as usize),
        ("firmware_request",        request_firmware        as *const () as usize),
        ("firmware_request_nowarn", request_firmware_direct as *const () as usize),
        ("release_firmware",        release_firmware        as *const () as usize),
    ] { export(name, addr, false); }
}

/// Install a firmware reader used before the rootfs fallback.
/// # C: O(1)
pub fn set_reader(reader: FirmwareReader) {
    *READER.lock() = Some(reader);
}

/// Clear the installed firmware reader.
/// # C: O(1)
pub fn clear_reader() {
    *READER.lock() = None;
}

extern "C" fn request_firmware(fw_out: *mut *const LinuxFirmware, name: *const c_char, _dev: *mut c_void) -> i32 {
    request_firmware_impl(fw_out, name)
}

extern "C" fn request_firmware_direct(fw_out: *mut *const LinuxFirmware, name: *const c_char, _dev: *mut c_void) -> i32 {
    request_firmware_impl(fw_out, name)
}

extern "C" fn release_firmware(fw: *const LinuxFirmware) {
    if fw.is_null() { return; }
    // SAFETY: request_firmware_impl returns a pointer to the first field of FirmwareAllocation; release_firmware is the matching ownership drop.
    drop(unsafe { Box::from_raw(fw as *mut FirmwareAllocation) });
}

fn request_firmware_impl(fw_out: *mut *const LinuxFirmware, name: *const c_char) -> i32 {
    if fw_out.is_null() || name.is_null() { return -LINUX_EINVAL; }
    // SAFETY: fw_out is caller-provided writable storage checked non-null.
    unsafe { *fw_out = null(); }
    let name = match cstr_bytes(name) {
        Some(n) if valid_fw_name(&n) => n,
        _ => return -LINUX_EINVAL,
    };
    let bytes = match read_named_firmware(&name) {
        Some(v) => v,
        None => return -LINUX_ENOENT,
    };
    let alloc = match allocate_firmware(bytes) {
        Some(v) => v,
        None => return -LINUX_ENOMEM,
    };
    // SAFETY: fw_out is caller-provided writable storage checked non-null.
    unsafe { *fw_out = alloc; }
    LINUX_OK
}

fn allocate_firmware(bytes: Vec<u8>) -> Option<*const LinuxFirmware> {
    let mut alloc = Box::new(FirmwareAllocation {
        fw: LinuxFirmware { size: bytes.len(), data: null(), pages: core::ptr::null_mut(), priv_data: core::ptr::null_mut() },
        bytes,
    });
    alloc.fw.data = alloc.bytes.as_ptr();
    alloc.fw.priv_data = (&mut *alloc) as *mut FirmwareAllocation as *mut c_void;
    Some(Box::into_raw(alloc) as *const LinuxFirmware)
}

fn read_named_firmware(name: &[u8]) -> Option<Vec<u8>> {
    for prefix in FW_PREFIXES {
        if let Some(path) = build_path(prefix, name) {
            if let Some(bytes) = read_path(&path) { return Some(bytes); }
        }
    }
    None
}

fn read_path(path: &[u8]) -> Option<Vec<u8>> {
    if let Some(reader) = *READER.lock() {
        if let Some(bytes) = reader(path) { return Some(bytes); }
    }
    ext4::rootfs::read_file(path)
}

fn build_path(prefix: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    let len = prefix.len().checked_add(name.len())?;
    if len >= PATH_MAX { return None; }
    let mut path = Vec::with_capacity(len);
    path.extend_from_slice(prefix);
    path.extend_from_slice(name);
    Some(path)
}

fn cstr_bytes(ptr: *const c_char) -> Option<Vec<u8>> {
    let p = ptr as *const u8;
    let mut len = 0usize;
    while len < CSTR_SCAN_MAX {
        // SAFETY: caller supplies a Linux C string; bounded scan stops at CSTR_SCAN_MAX or NUL.
        if unsafe { *p.add(len) } == 0 {
            // SAFETY: bytes before the first NUL are readable by the same Linux C-string contract.
            return Some(unsafe { core::slice::from_raw_parts(p, len) }.to_vec());
        }
        len += 1;
    }
    None
}

fn valid_fw_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > FW_NAME_MAX { return false; }
    if name[0] == b'/' { return false; }
    for part in name.split(|b| *b == b'/') {
        if part.is_empty() || part == b"." || part == b".." { return false; }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    const SAMPLE_FW: &[u8] = b"sample-firmware";

    fn test_reader(path: &[u8]) -> Option<Vec<u8>> {
        if path == b"/lib/firmware/rtl/driver.bin" { Some(SAMPLE_FW.to_vec()) } else { None }
    }

    #[test]
    fn request_firmware_uses_search_path() {
        set_reader(test_reader);
        let mut fw: *const LinuxFirmware = core::ptr::null();
        let rc = request_firmware(&mut fw, c"rtl/driver.bin".as_ptr(), null_mut());
        assert_eq!(rc, LINUX_OK);
        assert!(!fw.is_null());
        // SAFETY: fw is non-null and owned until release_firmware below.
        let got = unsafe { core::slice::from_raw_parts((*fw).data, (*fw).size) };
        assert_eq!(got, SAMPLE_FW);
        release_firmware(fw);
        clear_reader();
    }

    #[test]
    fn parent_path_is_rejected() {
        let mut fw: *const LinuxFirmware = core::ptr::null();
        let rc = request_firmware(&mut fw, c"../driver.bin".as_ptr(), null_mut());
        assert_eq!(rc, -LINUX_EINVAL);
        assert!(fw.is_null());
    }

    #[test]
    fn missing_firmware_clears_output() {
        clear_reader();
        let mut fw: *const LinuxFirmware = core::ptr::dangling();
        let rc = request_firmware_direct(&mut fw, c"missing.bin".as_ptr(), null_mut());
        assert_eq!(rc, -LINUX_ENOENT);
        assert!(fw.is_null());
    }
}
