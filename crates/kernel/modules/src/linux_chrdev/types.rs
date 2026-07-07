use core::ffi::{c_char, c_void};

pub(super) const LINUX_OK: i32 = 0;
pub(super) const LINUX_EINVAL: i32 = 22;
pub(super) const LINUX_ENODEV: i32 = 19;
pub(super) const LINUX_ENOMEM: i32 = 12;
pub(super) const LINUX_EBUSY: i32 = 16;
pub(super) const LINUX_ENXIO: i32 = 6;

pub(super) const LINUX_MINORBITS: u32 = 20;
pub(super) const LINUX_MINORMASK: u32 = (1 << LINUX_MINORBITS) - 1;
pub(super) const LINUX_MAJOR_DYNAMIC: u32 = 0;
pub(super) const LINUX_MAJOR_FIRST_DYNAMIC: u32 = 1;
pub(super) const LINUX_MAJOR_MAX: u32 = 4095;
pub(super) const LINUX_MINOR_FIRST: u32 = 0;
pub(super) const LINUX_MINOR_SPAN: u32 = 1 << LINUX_MINORBITS;
pub(super) const LINUX_MISC_MAJOR: u32 = 10;
pub(super) const LINUX_MISC_DYNAMIC_MINOR: i32 = 255;
pub(super) const LINUX_MISC_MIN_VALID_MINOR: i32 = 0;
pub(super) const LINUX_MISC_FIRST_DYNAMIC_MINOR: u32 = 0;
pub(super) const LINUX_MISC_MAX_DYNAMIC_MINOR: u32 = 255;
pub(super) const LINUX_MISC_MINOR_COUNT: u32 = 1;
pub(super) const LINUX_MISC_DEFAULT_MODE: u16 = 0o600;
pub(super) const LINUX_FIELD_CLEAR: u32 = 0;
pub(super) const LINUX_FIELD_SET: u32 = 1;

#[repr(C)]
pub(super) struct LinuxInode {
    pub(super) i_rdev: u32,
    pub(super) private: *mut c_void,
}

#[repr(C)]
pub(super) struct LinuxFile {
    pub(super) private_data: *mut c_void,
}

pub(super) type LinuxOpen = unsafe extern "C" fn(*mut LinuxInode, *mut LinuxFile) -> i32;
pub(super) type LinuxRelease = unsafe extern "C" fn(*mut LinuxInode, *mut LinuxFile) -> i32;
pub(super) type LinuxRead = unsafe extern "C" fn(*mut LinuxFile, *mut c_char, usize, *mut i64) -> isize;
pub(super) type LinuxWrite = unsafe extern "C" fn(*mut LinuxFile, *const c_char, usize, *mut i64) -> isize;
pub(super) type LinuxIoctl = unsafe extern "C" fn(*mut LinuxFile, u32, usize) -> isize;
pub(super) type LinuxPoll = unsafe extern "C" fn(*mut LinuxFile, *mut c_void) -> u32;
pub(super) type LinuxMmap = unsafe extern "C" fn(*mut LinuxFile, *mut c_void) -> i32;

#[repr(C)]
pub(super) struct LinuxFileOperations {
    pub(super) owner: *mut c_void,
    pub(super) open: Option<LinuxOpen>,
    pub(super) read: Option<LinuxRead>,
    pub(super) write: Option<LinuxWrite>,
    pub(super) unlocked_ioctl: Option<LinuxIoctl>,
    pub(super) release: Option<LinuxRelease>,
    pub(super) poll: Option<LinuxPoll>,
    pub(super) mmap: Option<LinuxMmap>,
    pub(super) llseek: *mut c_void,
}

unsafe impl Sync for LinuxFileOperations {}

#[repr(C)]
pub(super) struct LinuxCdev {
    pub(super) ops: *const LinuxFileOperations,
    pub(super) owner: *mut c_void,
    pub(super) dev: u32,
    pub(super) count: u32,
    pub(super) added: u32,
    pub(super) private: *mut c_void,
}

#[repr(C)]
pub(super) struct LinuxMiscDevice {
    pub(super) minor: i32,
    pub(super) name: *const c_char,
    pub(super) fops: *const LinuxFileOperations,
    pub(super) parent: *mut c_void,
    pub(super) this_device: *mut c_void,
    pub(super) mode: u16,
    pub(super) nodename: *const c_char,
    pub(super) cdev: LinuxCdev,
    pub(super) registered: u32,
}

/// Linux kernel `MKDEV`.
/// # C: O(1)
pub(super) const fn mkdev(major: u32, minor: u32) -> u32 {
    (major << LINUX_MINORBITS) | (minor & LINUX_MINORMASK)
}

/// Linux kernel `MAJOR`.
/// # C: O(1)
pub(super) const fn major(dev: u32) -> u32 { dev >> LINUX_MINORBITS }

/// Linux kernel `MINOR`.
/// # C: O(1)
pub(super) const fn minor(dev: u32) -> u32 { dev & LINUX_MINORMASK }
