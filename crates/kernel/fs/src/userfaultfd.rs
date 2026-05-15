// userfaultfd per `27` — first cut for v2 phase 28.
//
// Linux userfaultfd lets userspace handle page faults for mapped
// regions: register a VA range with the fd, then when a fault hits
// that range the kernel blocks the faulting task and emits an
// `uffd_msg` describing the fault on the fd's read queue. Userspace
// reads the message, materializes the page contents (read from
// network, copy from another buffer, zero, etc.), then issues
// UFFDIO_COPY or UFFDIO_ZEROPAGE to install the bytes and wake the
// blocked task.
//
// v1 implementation:
//   * userfaultfd(2) returns an fd backed by a UserfaultFdInode.
//   * UFFDIO_API ioctl: returns features=0 (minimum baseline).
//   * UFFDIO_REGISTER ioctl: records the (range, mode) on the inode.
//   * UFFDIO_UNREGISTER ioctl: removes a registered range.
//   * UFFDIO_COPY ioctl: byte-copies user-supplied source into the
//     destination range (which the caller may or may not have already
//     fault-populated). For v1 the caller's AS is the active CR3 so
//     we copy through it directly.
//   * UFFDIO_ZEROPAGE ioctl: zeros the destination range.
//   * read(fd, buf, len): drains queued events. Empty → -EAGAIN.
//
// Deferred follow-up: page-fault interception. v1 demand-fault
// handler in `vmm::AddressSpace::handle_page_fault` still zero-fills
// for anonymous VMAs even when the VA is in a UFFD-registered
// range. Real fault-routing requires that the demand-fault handler
// consult the registry, queue an event on the fd, and block the
// faulting task until userspace responds. The ioctl surface here is
// compatible with that future integration — the registered_ranges
// data structure is already in place.


#![allow(dead_code)]


use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU16, Ordering};

use sync::{Spinlock, TaskList as UffdLockClass};

const UFFD_API_FEATURE_SET: u64 = 0;

/// `struct uffd_msg` (Linux) — 32 bytes per event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UffdMsg {
    pub event:  u8,
    pub _r0:    u8,
    pub _r1:    u16,
    pub _r2:    u32,
    pub addr:   u64,
    pub flags:  u64,
    pub ptid:   u64,
}

const UFFD_EVENT_PAGEFAULT: u8 = 0x12;

/// `struct uffdio_api` — 16 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct UffdioApi  { api: u64, features: u64 }

/// `struct uffdio_register` — 32 bytes.
#[repr(C)]
struct UffdioRegister {
    range:  UffdioRange,
    mode:   u64,
    ioctls: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct UffdioRange { start: u64, len: u64 }

/// `struct uffdio_copy` — 40 bytes.
#[repr(C)]
struct UffdioCopy {
    dst:    u64,
    src:    u64,
    len:    u64,
    mode:   u64,
    copy:   u64,
}

/// `struct uffdio_zeropage` — 32 bytes.
#[repr(C)]
struct UffdioZeropage {
    range: UffdioRange,
    mode:  u64,
    zeropage: u64,
}

pub struct RegisteredRange {
    pub start: u64,
    pub end:   u64,
    pub mode:  u64,
}

pub struct UfState {
    pub api_set:    bool,
    pub ranges:     Vec<RegisteredRange>,
    pub events:     VecDeque<UffdMsg>,
}

pub struct UserfaultFdInode {
    pub state:   Spinlock<UfState, UffdLockClass>,
    pub flags:   AtomicU16,
}

impl UserfaultFdInode {
    /// # C: O(1)
    pub fn new(flags: u16) -> Arc<Self> {
        Arc::new(Self {
            state: Spinlock::new(UfState {
                api_set: false,
                ranges:  Vec::new(),
                events:  VecDeque::new(),
            }),
            flags: AtomicU16::new(flags),
        })
    }
}

impl vfs::Inode for UserfaultFdInode {
    fn ino(&self) -> vfs::Ino {
        // High-bits tag distinct from socket / io_uring / pipe inodes.
        0x5546_4644_0000_0000u64 | (self as *const _ as u64 & 0xFFFF_FFFF) as vfs::Ino
    }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    /// Drain the next queued uffd_msg. Empty queue → Eagain.
    fn read(&self, _o: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        if buf.len() < core::mem::size_of::<UffdMsg>() { return Err(vfs::VfsError::Einval); }
        let mut g = self.state.lock();
        // Empty event queue → 0 (Linux returns -EAGAIN; v1 vfs doesn't
        // expose Eagain so we return 0 — caller treats it as "no events").
        let msg = match g.events.pop_front() {
            Some(m) => m, None => return Ok(0),
        };
        // SAFETY: UffdMsg is repr(C) + Copy; transmute_copy reads exactly size_of::<UffdMsg>() bytes from a properly-aligned source we just popped from the event queue.
        let bytes: [u8; core::mem::size_of::<UffdMsg>()] = unsafe { core::mem::transmute_copy(&msg) };
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
    fn write(&self, _o: u64, _b: &[u8]) -> vfs::KResult<usize> { Err(vfs::VfsError::Einval) }
}

const UFFDIO_API:        u64 = 0xc018_aa3f;
const UFFDIO_REGISTER:   u64 = 0xc020_aa00;
const UFFDIO_UNREGISTER: u64 = 0x8010_aa01;
const UFFDIO_COPY:       u64 = 0xc028_aa03;
const UFFDIO_ZEROPAGE:   u64 = 0xc020_aa04;
const UFFDIO_WAKE:       u64 = 0x8010_aa02;

/// `userfaultfd(flags)` — slot 323. Returns a fresh fd.
/// # C: O(1)
pub fn sys_userfaultfd(args: &syscall::SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    use syscall::errno::Errno;
    const O_NONBLOCK: u64 = 0o0_004_000;
    const O_CLOEXEC:  u64 = 0o2_000_000;
    let raw   = args.a0;
    let flags = raw as u16;
    let inode = UserfaultFdInode::new(flags);
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode_ref: vfs::InodeRef = inode as vfs::InodeRef;
    let dentry = Dentry::new(None, "[uffd]".to_string(), inode_ref.clone());
    let mut fl = OpenFlags::O_RDWR;
    if (raw & O_NONBLOCK) != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode_ref, dentry, fl);
    match fdt.alloc(file) {
        Ok(fd) => {
            if (raw & O_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// Lift a generic `vfs::InodeRef` to `Arc<UserfaultFdInode>` by ino tag.
fn as_uffd(inode: &vfs::InodeRef) -> Option<Arc<UserfaultFdInode>> {
    if (inode.ino() & 0xFFFF_FFFF_0000_0000) != 0x5546_4644_0000_0000 {
        return None;
    }
    let raw = Arc::into_raw(inode.clone());
    // SAFETY: ino tag check above confirms this inode is a UserfaultFdInode; Arc::clone before into_raw bumped the refcount; from_raw consumes a balanced strong count.
    Some(unsafe { Arc::from_raw(raw as *const UserfaultFdInode) })
}

/// `ioctl(uffd_fd, UFFDIO_*, arg)` — handled by the generic ioctl
/// dispatch when the fd's inode is a UserfaultFdInode.
/// # C: O(K) for COPY/ZEROPAGE, O(1) otherwise
pub fn handle_uffd_ioctl(inode: &vfs::InodeRef, req: u64, arg: u64) -> i64 {
    use syscall::errno::Errno;
    let ufd = match as_uffd(inode) { Some(u) => u, None => return -(Errno::Enotty.as_i32() as i64) };
    if arg == 0 || arg >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    match req {
        UFFDIO_API => {
            // SAFETY: arg validated < USER_VA_END; UffdioApi is 16 bytes; CPL=0 reads through caller's AS.
            let mut api: UffdioApi = unsafe { core::ptr::read_volatile(arg as *const UffdioApi) };
            api.features = UFFD_API_FEATURE_SET;
            // SAFETY: same range; CPL=0 writes back the negotiated fields.
            unsafe { core::ptr::write_volatile(arg as *mut UffdioApi, api); }
            ufd.state.lock().api_set = true;
            0
        }
        UFFDIO_REGISTER => {
            // SAFETY: arg validated < USER_VA_END; UffdioRegister is 32 bytes; CPL=0 reads.
            let mut reg: UffdioRegister = unsafe {
                core::ptr::read_volatile(arg as *const UffdioRegister)
            };
            let start = reg.range.start;
            let end   = start.saturating_add(reg.range.len);
            if start == 0 || end <= start || end >= hal::USER_VA_END
               || (start & 0xFFF) != 0 || (reg.range.len & 0xFFF) != 0 {
                return -(Errno::Einval.as_i32() as i64);
            }
            ufd.state.lock().ranges.push(RegisteredRange { start, end, mode: reg.mode });
            // Report supported ioctls bitmap: COPY | ZEROPAGE | WAKE.
            reg.ioctls = (1u64 << 1) | (1u64 << 2) | (1u64 << 3);
            // SAFETY: arg+24 within 32-byte UffdioRegister; aligned u64 write.
            unsafe { core::ptr::write_volatile((arg + 24) as *mut u64, reg.ioctls); }
            0
        }
        UFFDIO_UNREGISTER => {
            // SAFETY: arg validated < USER_VA_END; UffdioRange is 16 bytes.
            let r: UffdioRange = unsafe { core::ptr::read_volatile(arg as *const UffdioRange) };
            let end = r.start.saturating_add(r.len);
            ufd.state.lock().ranges.retain(|reg| !(reg.start == r.start && reg.end == end));
            0
        }
        UFFDIO_COPY => {
            // SAFETY: arg validated < USER_VA_END; UffdioCopy is 40 bytes; CPL=0 reads.
            let mut c: UffdioCopy = unsafe { core::ptr::read_volatile(arg as *const UffdioCopy) };
            if c.dst == 0 || c.src == 0 || c.len == 0
               || c.dst.checked_add(c.len).map_or(true, |e| e >= hal::USER_VA_END)
               || c.src.checked_add(c.len).map_or(true, |e| e >= hal::USER_VA_END)
            {
                return -(Errno::Efault.as_i32() as i64);
            }
            // SAFETY: src + dst + len validated < USER_VA_END; both live in caller's AS (active CR3); CPL=0 byte copy.
            unsafe {
                for i in 0..c.len {
                    let b = core::ptr::read_volatile((c.src + i) as *const u8);
                    core::ptr::write_volatile((c.dst + i) as *mut u8, b);
                }
            }
            c.copy = c.len as u64;
            // SAFETY: arg+32 within UffdioCopy; aligned u64 writeback.
            unsafe { core::ptr::write_volatile((arg + 32) as *mut u64, c.copy); }
            c.len as i64
        }
        UFFDIO_ZEROPAGE => {
            // SAFETY: arg validated < USER_VA_END; UffdioZeropage is 32 bytes.
            let mut z: UffdioZeropage = unsafe {
                core::ptr::read_volatile(arg as *const UffdioZeropage)
            };
            let start = z.range.start;
            let len   = z.range.len;
            if start == 0 || len == 0
               || start.checked_add(len).map_or(true, |e| e >= hal::USER_VA_END)
            {
                return -(Errno::Efault.as_i32() as i64);
            }
            // SAFETY: range validated < USER_VA_END; CPL=0 writes through caller's AS.
            unsafe {
                for i in 0..len {
                    core::ptr::write_volatile((start + i) as *mut u8, 0);
                }
            }
            z.zeropage = len as u64;
            // SAFETY: arg+24 within UffdioZeropage; aligned u64 writeback.
            unsafe { core::ptr::write_volatile((arg + 24) as *mut u64, z.zeropage); }
            len as i64
        }
        UFFDIO_WAKE => 0,
        _ => -(Errno::Enotty.as_i32() as i64),
    }
}
