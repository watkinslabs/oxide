use super::*;
use crate::linux_device::types::LinuxKobject;
use alloc::sync::Arc;
use core::ffi::c_char;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

const TEST_MAJOR_A: u32 = 901;
const TEST_MAJOR_B: u32 = 902;
const TEST_MINOR_BASE: u32 = 7;
const TEST_MINOR_COUNT: u32 = 3;
const TEST_BUFFER_LEN: usize = 4;
const TEST_IOCTL_CMD: u32 = 0x5843_4445;
const TEST_IOCTL_ARG: usize = 0x1234;
const TEST_IOCTL_RET: isize = 0x55;
const TEST_PRIVATE_OPEN: usize = 0xabc0;
const TEST_PRIVATE_RW: usize = 0xdef0;
const READ_BYTE: u8 = b'R';
const POLL_BYTE: u8 = b'P';

static OPEN_COUNT: AtomicUsize = AtomicUsize::new(0);
static RELEASE_COUNT: AtomicUsize = AtomicUsize::new(0);
static POLL_COUNT: AtomicUsize = AtomicUsize::new(0);
static MMAP_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn sample_open(_inode: *mut LinuxInode, file: *mut LinuxFile) -> i32 {
    if file.is_null() { return -LINUX_EINVAL; }
    // SAFETY: file is checked non-null and points at callback-local file storage.
    unsafe { (*file).private_data = TEST_IOCTL_ARG as *mut _; }
    LINUX_OK
}

unsafe extern "C" fn sample_read(_file: *mut LinuxFile, buf: *mut c_char, count: usize, _pos: *mut i64) -> isize {
    if buf.is_null() || count == 0 { return -LINUX_EINVAL as isize; }
    // SAFETY: VFS adapter passes a writable buffer of count bytes.
    unsafe { *buf = READ_BYTE as c_char; }
    1
}

unsafe extern "C" fn sample_write(_file: *mut LinuxFile, buf: *const c_char, count: usize, _pos: *mut i64) -> isize {
    if buf.is_null() { return -LINUX_EINVAL as isize; }
    count as isize
}

unsafe extern "C" fn sample_ioctl(_file: *mut LinuxFile, cmd: u32, arg: usize) -> isize {
    if cmd == TEST_IOCTL_CMD && arg == TEST_IOCTL_ARG { TEST_IOCTL_RET } else { -LINUX_EINVAL as isize }
}

static FOPS: LinuxFileOperations = LinuxFileOperations {
    owner: null_mut(),
    open: Some(sample_open),
    read: Some(sample_read),
    write: Some(sample_write),
    unlocked_ioctl: Some(sample_ioctl),
    release: None,
    poll: None,
    mmap: None,
    llseek: null_mut(),
};

unsafe extern "C" fn state_open(_inode: *mut LinuxInode, file: *mut LinuxFile) -> i32 {
    if file.is_null() { return -LINUX_EINVAL; }
    OPEN_COUNT.fetch_add(1, Ordering::SeqCst);
    // SAFETY: file is checked non-null and points at callback-local file storage.
    unsafe { (*file).private_data = TEST_PRIVATE_OPEN as *mut _; }
    LINUX_OK
}

unsafe extern "C" fn state_read(file: *mut LinuxFile, buf: *mut c_char, count: usize, _pos: *mut i64) -> isize {
    if file.is_null() || buf.is_null() || count == 0 { return -LINUX_EINVAL as isize; }
    // SAFETY: callback arguments are checked non-null and buf covers count bytes from the VFS adapter.
    unsafe {
        if (*file).private_data as usize != TEST_PRIVATE_OPEN { return -LINUX_EINVAL as isize; }
        *buf = POLL_BYTE as c_char;
        (*file).private_data = TEST_PRIVATE_RW as *mut _;
    }
    1
}

unsafe extern "C" fn state_poll(file: *mut LinuxFile, _wait: *mut core::ffi::c_void) -> u32 {
    if file.is_null() { return 0; }
    // SAFETY: file is checked non-null and points at callback-local file storage.
    unsafe {
        if (*file).private_data as usize == TEST_PRIVATE_RW {
            POLL_COUNT.fetch_add(1, Ordering::SeqCst);
            vfs::POLL_IN
        } else { 0 }
    }
}

unsafe extern "C" fn state_mmap(_file: *mut LinuxFile, _vma: *mut core::ffi::c_void) -> i32 {
    MMAP_COUNT.fetch_add(1, Ordering::SeqCst);
    LINUX_OK
}

unsafe extern "C" fn state_release(_inode: *mut LinuxInode, file: *mut LinuxFile) -> i32 {
    if file.is_null() { return -LINUX_EINVAL; }
    // SAFETY: file is checked non-null and points at callback-local file storage.
    unsafe {
        if (*file).private_data as usize == TEST_PRIVATE_RW {
            RELEASE_COUNT.fetch_add(1, Ordering::SeqCst);
            (*file).private_data = null_mut();
            LINUX_OK
        } else { -LINUX_EINVAL }
    }
}

static STATE_FOPS: LinuxFileOperations = LinuxFileOperations {
    owner: null_mut(),
    open: Some(state_open),
    read: Some(state_read),
    write: None,
    unlocked_ioctl: None,
    release: Some(state_release),
    poll: Some(state_poll),
    mmap: Some(state_mmap),
    llseek: null_mut(),
};

fn new_cdev() -> LinuxCdev {
    LinuxCdev { kobj: LinuxKobject::new(), ops: core::ptr::null(), owner: null_mut(), dev: 0, count: 0, added: 0, private: null_mut() }
}

#[test]
fn cdev_add_routes_vfs_calls() {
    let mut cdev = new_cdev();
    cdev_init(&mut cdev, &FOPS);
    let dev = mkdev(TEST_MAJOR_A, TEST_MINOR_BASE);
    assert_eq!(register_chrdev_region(dev, TEST_MINOR_COUNT, core::ptr::null()), LINUX_OK);
    assert_eq!(cdev_add(&mut cdev, dev, TEST_MINOR_COUNT), LINUX_OK);
    assert_eq!(cdev.kobj.refcount, 1);
    let ops = vfs::lookup_chrdev(Devt::from_kdev(mkdev(TEST_MAJOR_A, TEST_MINOR_BASE + 1))).expect("registered cdev region");
    assert_eq!(ops.open(Devt::from_kdev(dev)), Ok(()));
    let mut buf = [0u8; TEST_BUFFER_LEN];
    assert_eq!(ops.read(Devt::from_kdev(dev), 0, &mut buf), Ok(1));
    assert_eq!(buf[0], READ_BYTE);
    assert_eq!(ops.write(Devt::from_kdev(dev), 0, &buf), Ok(TEST_BUFFER_LEN));
    assert_eq!(ops.ioctl(Devt::from_kdev(dev), TEST_IOCTL_CMD, TEST_IOCTL_ARG), Ok(TEST_IOCTL_RET as usize));
    cdev_del(&mut cdev);
    assert_eq!(cdev.kobj.refcount, 0);
    unregister_chrdev_region(dev, TEST_MINOR_COUNT);
    assert!(vfs::lookup_chrdev(Devt::from_kdev(dev)).is_none());
}

#[test]
fn overlapping_cdev_region_is_busy() {
    let mut one = new_cdev();
    let mut two = new_cdev();
    cdev_init(&mut one, &FOPS);
    cdev_init(&mut two, &FOPS);
    let dev = mkdev(TEST_MAJOR_B, TEST_MINOR_BASE);
    assert_eq!(register_chrdev_region(dev, TEST_MINOR_COUNT, core::ptr::null()), LINUX_OK);
    assert_eq!(cdev_add(&mut one, dev, TEST_MINOR_COUNT), LINUX_OK);
    assert_eq!(cdev_add(&mut two, dev, TEST_MINOR_COUNT), -LINUX_EBUSY);
    cdev_del(&mut one);
    unregister_chrdev_region(dev, TEST_MINOR_COUNT);
}

#[test]
fn dynamic_major_allocation_writes_dev() {
    let mut dev = 0u32;
    assert_eq!(alloc_chrdev_region(&mut dev, TEST_MINOR_BASE, TEST_MINOR_COUNT, core::ptr::null()), LINUX_OK);
    assert_ne!(major(dev), LINUX_MAJOR_DYNAMIC);
    assert_eq!(minor(dev), TEST_MINOR_BASE);
    unregister_chrdev_region(dev, TEST_MINOR_COUNT);
}

#[test]
fn device_node_routes_open_state_poll_mmap_and_release() {
    OPEN_COUNT.store(0, Ordering::SeqCst);
    RELEASE_COUNT.store(0, Ordering::SeqCst);
    POLL_COUNT.store(0, Ordering::SeqCst);
    MMAP_COUNT.store(0, Ordering::SeqCst);

    let mut cdev = new_cdev();
    cdev_init(&mut cdev, &STATE_FOPS);
    let dev = mkdev(903, 1);
    assert_eq!(register_chrdev_region(dev, 1, core::ptr::null()), LINUX_OK);
    assert_eq!(cdev_add(&mut cdev, dev, 1), LINUX_OK);

    let inode = vfs::make_device_node_inode(0x6640, vfs::FileType::CharDev, Devt::from_kdev(dev), 0o600, alloc::sync::Weak::new());
    let dentry = vfs::Dentry::new(None, "linux-state-char".into(), Arc::clone(&inode));
    let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDONLY);
    assert_eq!(file.open_hook(), Ok(()));
    assert_eq!(OPEN_COUNT.load(Ordering::SeqCst), 1);
    assert_eq!(file.private_data(), TEST_PRIVATE_OPEN as u64);

    let mut buf = [0u8; 1];
    assert_eq!(file.read(&mut buf), Ok(1));
    assert_eq!(buf[0], POLL_BYTE);
    assert_eq!(file.private_data(), TEST_PRIVATE_RW as u64);
    assert_eq!(file.poll(), vfs::POLL_IN);
    assert_eq!(POLL_COUNT.load(Ordering::SeqCst), 1);
    assert_eq!(file.inode().mmap_shared_frame(0), Ok(None));
    assert_eq!(MMAP_COUNT.load(Ordering::SeqCst), 1);

    drop(file);
    assert_eq!(RELEASE_COUNT.load(Ordering::SeqCst), 1);
    cdev_del(&mut cdev);
    unregister_chrdev_region(dev, 1);
}
