use super::*;
use core::sync::atomic::{AtomicU32, Ordering};
use vfs::{FdTable, OpenFlags, VfsError};
use vfs::Dentry;
use vfs::file::install_open_at;

// Every test below drives the SAME module-level callback counters (RELEASES,
// LINKS, MAKE_GROUPS, ...): each stores 0, runs a configfs operation, then
// asserts an exact count. cargo runs a binary's tests on parallel threads, so
// without this one test's reset lands inside another's measurement window.
//
// The counters cannot be made test-local: they are written from `extern "C"`
// configfs callbacks whose signatures are fixed by the kernel ABI this file
// exists to conform to, and the only per-item slot that could carry a context
// (`ConfigItem::private`) is itself ABI surface under test here.
//
// Poison is recovered rather than propagated: a genuine assertion failure in
// one test must report as ONE failure, not cascade into every sibling.
static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

static ATTR_NAME: &[u8] = b"value\0";
static BIN_NAME: &[u8] = b"blob\0";
static CHILD_NAME: &[u8] = b"child\0";
static GROUP_NAME: &[u8] = b"sample\0";
static GROUP_LINK_NAME: &[u8] = b"sample_link\0";
static GROUP_MKDIR_NAME: &[u8] = b"sample_mkdir\0";
static RELEASES: AtomicU32 = AtomicU32::new(0);
static LINKS: AtomicU32 = AtomicU32::new(0);
static MAKE_GROUPS: AtomicU32 = AtomicU32::new(0);
static DROP_ITEMS: AtomicU32 = AtomicU32::new(0);
static SHOWS: AtomicU32 = AtomicU32::new(0);
static ACTIVE_RELEASES: AtomicU32 = AtomicU32::new(0);
static BIN_WRITES: AtomicU32 = AtomicU32::new(0);
static BIN_WRITTEN_LEN: AtomicU32 = AtomicU32::new(0);
static MADE_GROUP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn show(_item: *mut ConfigItem, buf: *mut c_char) -> isize {
    SHOWS.fetch_add(1, Ordering::AcqRel);
    let body = b"ok\n";
    // SAFETY: configfs passes a page-sized writable kernel buffer.
    unsafe { core::ptr::copy_nonoverlapping(body.as_ptr(), buf as *mut u8, body.len()); }
    body.len() as isize
}

unsafe extern "C" fn bin_read(
    _item: *mut ConfigItem,
    _private: *mut c_void,
    _buf: *mut c_void,
    out: *mut c_char,
    off: i64,
    count: usize,
) -> isize {
    let body = b"binary";
    let off = off.max(0) as usize;
    if off >= body.len() { return 0; }
    let n = (body.len() - off).min(count);
    // SAFETY: configfs passes a writable kernel buffer of count bytes.
    unsafe { core::ptr::copy_nonoverlapping(body[off..off + n].as_ptr(), out as *mut u8, n); }
    n as isize
}

unsafe extern "C" fn bin_write(
    _item: *mut ConfigItem,
    _private: *mut c_void,
    _buf: *mut c_void,
    input: *const c_char,
    _off: i64,
    count: usize,
) -> isize {
    BIN_WRITES.fetch_add(1, Ordering::AcqRel);
    BIN_WRITTEN_LEN.store(count as u32, Ordering::Release);
    assert!(!input.is_null());
    count as isize
}

unsafe extern "C" fn release(_item: *mut ConfigItem) {
    RELEASES.fetch_add(1, Ordering::AcqRel);
}

unsafe extern "C" fn active_release(_item: *mut ConfigItem) {
    ACTIVE_RELEASES.fetch_add(1, Ordering::AcqRel);
}

unsafe extern "C" fn allow_link(_parent: *mut ConfigItem, _target: *mut ConfigItem) -> i32 {
    LINKS.fetch_add(1, Ordering::AcqRel);
    0
}

unsafe extern "C" fn drop_link(_parent: *mut ConfigItem, _target: *mut ConfigItem) -> i32 {
    LINKS.fetch_add(1, Ordering::AcqRel);
    0
}

unsafe extern "C" fn make_group(_parent: *mut ConfigGroup, _name: *const c_char) -> *mut ConfigGroup {
    MAKE_GROUPS.fetch_add(1, Ordering::AcqRel);
    MADE_GROUP.load(Ordering::Acquire) as *mut ConfigGroup
}

unsafe extern "C" fn drop_item(_parent: *mut ConfigGroup, _item: *mut ConfigItem) {
    DROP_ITEMS.fetch_add(1, Ordering::AcqRel);
}


// Module manifest:
// - `surface`: the exported-symbol surface.
// - `groups`: subsystem/default-group registration, mkdir/rmdir, detach.
// - `items`: config_item naming, refcounts, and default-group teardown.
// - `attrs`: attribute open/active-reference and binary-attribute writes.
mod surface;
mod groups;
mod items;
mod attrs;
