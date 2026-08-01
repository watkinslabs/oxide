// Linux firmware-loader KPI facade.
//
// Owned responsibilities:
// - C ABI structs and exported request/release entry points.
// - Linux firmware search-path construction.
// - Initramfs-reader hook, cache, async callback queue, and rootfs fallback.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{c_char, c_void};
use core::ptr::null;
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Modules as ModulesLockClass, Spinlock};

const LINUX_OK: i32 = 0;
const LINUX_EINVAL: i32 = 22;
const LINUX_ENOENT: i32 = 2;
const LINUX_ENOMEM: i32 = 12;
const LINUX_ERANGE: i32 = 34;

const FW_ACTION_NOUEVENT: i32 = 0;
const FW_ACTION_UEVENT: i32 = 1;
const PATH_MAX: usize = 4096;
const FW_NAME_MAX: usize = 255;
const CSTR_SCAN_MAX: usize = PATH_MAX;
const FW_PREFIXES: [&[u8]; 3] = [b"/lib/firmware/updates/", b"/lib/firmware/", b"/usr/lib/firmware/"];

type FirmwareReader = fn(&[u8]) -> Option<Vec<u8>>;
type FirmwareCont = extern "C" fn(*const LinuxFirmware, *mut c_void);

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

struct CacheEntry {
    name: Vec<u8>,
    bytes: Vec<u8>,
}

struct AsyncRequest {
    name: Vec<u8>,
    context: usize,
    cont: FirmwareCont,
}

static INITRAMFS_READER: Spinlock<Option<FirmwareReader>, ModulesLockClass> = Spinlock::new(None);
static CACHE: Spinlock<Vec<CacheEntry>, ModulesLockClass> = Spinlock::new(Vec::new());
static ASYNC: Spinlock<Vec<AsyncRequest>, ModulesLockClass> = Spinlock::new(Vec::new());
static WORKER_STARTED: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "oxide-kernel")]
static ASYNC_WAIT: sched::live::WaitList = sched::live::WaitList::new();

/// Register Linux firmware KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    init_async_worker();
    use crate::symtab::export;
    for (name, addr) in [
        ("request_firmware",        request_firmware        as *const () as usize),
        ("request_firmware_direct", request_firmware_direct as *const () as usize),
        ("firmware_request",        request_firmware        as *const () as usize),
        ("firmware_request_nowarn", firmware_request_nowarn as *const () as usize),
        ("firmware_request_platform", firmware_request_platform as *const () as usize),
        ("firmware_request_cache",  firmware_request_cache  as *const () as usize),
        ("request_firmware_nowait", request_firmware_nowait as *const () as usize),
        ("firmware_request_nowait_nowarn", firmware_request_nowait_nowarn as *const () as usize),
        ("request_firmware_into_buf", request_firmware_into_buf as *const () as usize),
        ("request_partial_firmware_into_buf", request_partial_firmware_into_buf as *const () as usize),
        ("release_firmware",        release_firmware        as *const () as usize),
    ] { export(name, addr, false); }
}

/// Install an initramfs/bootloader firmware reader used before rootfs fallback.
/// # C: O(1)
pub fn set_initramfs_reader(reader: FirmwareReader) { *INITRAMFS_READER.lock() = Some(reader); }

/// Backward-compatible alias for existing boot code/tests.
/// # C: O(1)
pub fn set_reader(reader: FirmwareReader) { set_initramfs_reader(reader); }

/// Clear the installed firmware reader.
/// # C: O(1)
pub fn clear_reader() { *INITRAMFS_READER.lock() = None; }

/// Test-only: empty the cache and drop the reader hook. Callers MUST hold the
/// firmware claim (`test_serial::firmware`).
/// # C: O(N_entries)
#[cfg(test)]
pub(crate) fn reset_for_test() { CACHE.lock().clear(); clear_reader(); }

extern "C" fn request_firmware(fw_out: *mut *const LinuxFirmware, name: *const c_char, _dev: *mut c_void) -> i32 {
    request_firmware_impl(fw_out, name)
}

extern "C" fn request_firmware_direct(fw_out: *mut *const LinuxFirmware, name: *const c_char, _dev: *mut c_void) -> i32 {
    request_firmware_impl(fw_out, name)
}

extern "C" fn request_firmware_into_buf(fw_out: *mut *const LinuxFirmware, name: *const c_char, _dev: *mut c_void, buf: *mut c_void, size: usize) -> i32 {
    request_partial_firmware_into_buf(fw_out, name, _dev, buf, size, 0)
}

extern "C" fn request_partial_firmware_into_buf(
    fw_out: *mut *const LinuxFirmware,
    name: *const c_char,
    _dev: *mut c_void,
    buf: *mut c_void,
    size: usize,
    offset: usize,
) -> i32 {
    if fw_out.is_null() || name.is_null() || (buf.is_null() && size != 0) { return -LINUX_EINVAL; }
    // SAFETY: fw_out is caller-provided writable storage checked non-null.
    unsafe { *fw_out = null(); }
    let name = match firmware_name(name) { Some(n) => n, None => return -LINUX_EINVAL };
    let bytes = match load_firmware_bytes(&name) {
        Some(v) => v,
        None => return -LINUX_ENOENT,
    };
    if offset > bytes.len() { return -LINUX_ERANGE; }
    let part = &bytes[offset..];
    if part.len() > size { return -LINUX_ENOMEM; }
    if !part.is_empty() {
        // SAFETY: buf is non-null when size is non-zero; part.len() <= size proves writable range.
        unsafe { core::ptr::copy_nonoverlapping(part.as_ptr(), buf.cast::<u8>(), part.len()); }
    }
    let alloc = match allocate_firmware_borrowed(part.len(), buf.cast::<u8>()) {
        Some(v) => v,
        None => return -LINUX_ENOMEM,
    };
    // SAFETY: fw_out is caller-provided writable storage checked non-null.
    unsafe { *fw_out = alloc; }
    LINUX_OK
}

extern "C" fn firmware_request_nowarn(fw_out: *mut *const LinuxFirmware, name: *const c_char, _dev: *mut c_void) -> i32 {
    request_firmware_impl(fw_out, name)
}

extern "C" fn firmware_request_platform(fw_out: *mut *const LinuxFirmware, name: *const c_char, _dev: *mut c_void) -> i32 {
    request_firmware_impl(fw_out, name)
}

extern "C" fn firmware_request_cache(_dev: *mut c_void, name: *const c_char) -> i32 {
    let name = match firmware_name(name) {
        Some(n) => n,
        None => return -LINUX_EINVAL,
    };
    match load_firmware_bytes(&name) {
        Some(_) => LINUX_OK,
        None => -LINUX_ENOENT,
    }
}

extern "C" fn request_firmware_nowait(
    _module: *mut c_void,
    uevent: bool,
    name: *const c_char,
    _dev: *mut c_void,
    _gfp: usize,
    context: *mut c_void,
    cont: Option<FirmwareCont>,
) -> i32 {
    let _ = if uevent { FW_ACTION_UEVENT } else { FW_ACTION_NOUEVENT };
    let Some(cont) = cont else { return -LINUX_EINVAL; };
    let name = match firmware_name(name) {
        Some(n) => n,
        None => return -LINUX_EINVAL,
    };
    ASYNC.lock().push(AsyncRequest { name, context: context as usize, cont });
    #[cfg(target_os = "oxide-kernel")]
    ASYNC_WAIT.wake_one();
    #[cfg(not(target_os = "oxide-kernel"))]
    drain_async_once();
    LINUX_OK
}

extern "C" fn firmware_request_nowait_nowarn(
    module: *mut c_void,
    name: *const c_char,
    dev: *mut c_void,
    gfp: usize,
    context: *mut c_void,
    cont: Option<FirmwareCont>,
) -> i32 {
    request_firmware_nowait(module, false, name, dev, gfp, context, cont)
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
    let name = match firmware_name(name) { Some(n) => n, None => return -LINUX_EINVAL };
    let bytes = match load_firmware_bytes(&name) {
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

fn init_async_worker() {
    if WORKER_STARTED.swap(true, Ordering::AcqRel) { return; }
    #[cfg(target_os = "oxide-kernel")]
    {
        let tid = sched::live::next_tid();
        // SAFETY: module exports initialise after the live runqueue exists; worker entry is static.
        let _ = unsafe { sched::live::spawn_kernel_thread(tid, "fw_loader", async_worker_entry, 0) };
    }
}

#[cfg(target_os = "oxide-kernel")]
extern "C" fn async_worker_entry(_arg: usize) -> ! {
    loop {
        while drain_async_once() {}
        // SAFETY: worker parks with no locks held and yields immediately.
        unsafe { ASYNC_WAIT.park(); sched::live::schedule(); }
    }
}

fn drain_async_once() -> bool {
    let req = ASYNC.lock().pop();
    let Some(req) = req else { return false; };
    let fw = load_firmware_bytes(&req.name).and_then(allocate_firmware).unwrap_or(null());
    (req.cont)(fw, req.context as *mut c_void);
    true
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

fn allocate_firmware_borrowed(size: usize, data: *const u8) -> Option<*const LinuxFirmware> {
    let mut alloc = Box::new(FirmwareAllocation {
        fw: LinuxFirmware { size, data, pages: core::ptr::null_mut(), priv_data: core::ptr::null_mut() },
        bytes: Vec::new(),
    });
    alloc.fw.priv_data = (&mut *alloc) as *mut FirmwareAllocation as *mut c_void;
    Some(Box::into_raw(alloc) as *const LinuxFirmware)
}

fn firmware_name(name: *const c_char) -> Option<Vec<u8>> {
    cstr_bytes(name).filter(|n| valid_fw_name(n))
}

fn load_firmware_bytes(name: &[u8]) -> Option<Vec<u8>> {
    if let Some(bytes) = cache_get(name) { return Some(bytes); }
    let bytes = read_named_firmware(name)?;
    cache_put(name, &bytes);
    Some(bytes)
}

fn cache_get(name: &[u8]) -> Option<Vec<u8>> {
    CACHE.lock().iter().find(|e| e.name == name).map(|e| e.bytes.clone())
}

fn cache_put(name: &[u8], bytes: &[u8]) {
    let mut g = CACHE.lock();
    if g.iter().any(|e| e.name == name) { return; }
    g.push(CacheEntry { name: name.to_vec(), bytes: bytes.to_vec() });
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
    if let Some(reader) = *INITRAMFS_READER.lock() {
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
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::ptr::null_mut;

    const SAMPLE_FW: &[u8] = b"sample-firmware";
    const ALT_FW: &[u8] = b"alt-firmware";
    static CALLBACKS: AtomicUsize = AtomicUsize::new(0);
    static LAST_CONTEXT: AtomicUsize = AtomicUsize::new(0);
    static LAST_SIZE: AtomicUsize = AtomicUsize::new(0);

    fn test_reader(path: &[u8]) -> Option<Vec<u8>> {
        match path {
            b"/lib/firmware/rtl/driver.bin" => Some(SAMPLE_FW.to_vec()),
            b"/usr/lib/firmware/alt.bin" => Some(ALT_FW.to_vec()),
            _ => None,
        }
    }

    extern "C" fn async_cb(fw: *const LinuxFirmware, context: *mut c_void) {
        CALLBACKS.fetch_add(1, Ordering::AcqRel);
        LAST_CONTEXT.store(context as usize, Ordering::Release);
        if !fw.is_null() {
            // SAFETY: callback owns the firmware pointer until release.
            unsafe { LAST_SIZE.store((*fw).size, Ordering::Release); }
            release_firmware(fw);
        }
    }

    #[test]
    fn request_firmware_uses_search_path() {
        let _modules = crate::test_serial::claim();
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
    fn firmware_cache_survives_reader_clear() {
        let _modules = crate::test_serial::claim();
        set_initramfs_reader(test_reader);
        assert_eq!(firmware_request_cache(null_mut(), c"alt.bin".as_ptr()), LINUX_OK);
        clear_reader();
        let mut fw: *const LinuxFirmware = core::ptr::null();
        let rc = request_firmware(&mut fw, c"alt.bin".as_ptr(), null_mut());
        assert_eq!(rc, LINUX_OK);
        assert!(!fw.is_null());
        release_firmware(fw);
    }

    #[test]
    fn request_firmware_nowait_invokes_callback() {
        let _modules = crate::test_serial::claim();
        CALLBACKS.store(0, Ordering::Release);
        LAST_CONTEXT.store(0, Ordering::Release);
        LAST_SIZE.store(0, Ordering::Release);
        set_reader(test_reader);
        let rc = request_firmware_nowait(null_mut(), true, c"rtl/driver.bin".as_ptr(), null_mut(), 0, 0x55usize as *mut c_void, Some(async_cb));
        assert_eq!(rc, LINUX_OK);
        assert_eq!(CALLBACKS.load(Ordering::Acquire), 1);
        assert_eq!(LAST_CONTEXT.load(Ordering::Acquire), 0x55);
        assert_eq!(LAST_SIZE.load(Ordering::Acquire), SAMPLE_FW.len());
        clear_reader();
    }

    #[test]
    fn request_firmware_into_buf_copies_without_owning_buffer() {
        let _modules = crate::test_serial::claim();
        set_reader(test_reader);
        let mut buf = [0u8; 8];
        let mut fw: *const LinuxFirmware = core::ptr::null();
        let rc = request_partial_firmware_into_buf(&mut fw, c"rtl/driver.bin".as_ptr(), null_mut(), buf.as_mut_ptr().cast(), buf.len(), 7);
        assert_eq!(rc, LINUX_OK);
        assert_eq!(&buf, b"firmware");
        assert!(!fw.is_null());
        // SAFETY: fw is non-null and points at caller-owned buf until release.
        assert_eq!(unsafe { (*fw).data }, buf.as_ptr());
        release_firmware(fw);
        clear_reader();
    }

    #[test]
    fn parent_path_is_rejected() {
        let _modules = crate::test_serial::claim();
        let mut fw: *const LinuxFirmware = core::ptr::null();
        let rc = request_firmware(&mut fw, c"../driver.bin".as_ptr(), null_mut());
        assert_eq!(rc, -LINUX_EINVAL);
        assert!(fw.is_null());
    }

    #[test]
    fn missing_firmware_clears_output() {
        let _modules = crate::test_serial::claim();
        clear_reader();
        let mut fw: *const LinuxFirmware = core::ptr::dangling();
        let rc = request_firmware_direct(&mut fw, c"missing.bin".as_ptr(), null_mut());
        assert_eq!(rc, -LINUX_ENOENT);
        assert!(fw.is_null());
    }
}
