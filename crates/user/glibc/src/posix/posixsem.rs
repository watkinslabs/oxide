// POSIX named semaphores <semaphore.h> sem_open/sem_close/sem_unlink
// (docs/59§6). A named sem is a 32-byte sem_t living in a shm file
// "/dev/shm/sem.<name>"; sem_open opens (creating + zero-init on O_CREAT) the
// file, mmaps it MAP_SHARED, and returns the mapped sem_t*. sem_wait/sem_post/
// sem_getvalue (rt/sem.rs) then operate on the mapped word via the futex. The
// unnamed-sem ops (sem_init/_wait/_post/_destroy/_getvalue) already exist in
// rt/sem; only the named-object lifecycle lands here.
#![cfg(feature = "freestanding")]
use crate::internal::errno::set;
use crate::posix::io::{openat, AT_FDCWD, O_CREAT, O_RDWR};
use crate::posix::mman::{mmap, munmap, MAP_FAILED, PROT_READ, PROT_WRITE};
use crate::posix::shm::{build_path, PATH_CAP};
use crate::rt::sem::sem_t;
use core::sync::atomic::{AtomicU32, Ordering};

const O_EXCL: i32 = 0o2000;
const O_CLOEXEC: i32 = 0o2000000;
const MAP_SHARED: i32 = 0x1;
const SEM_T_SZ: usize = 32;
// sem_open returns (sem_t *) -1 on error.
pub const SEM_FAILED: *mut sem_t = usize::MAX as *mut sem_t;

// # C: sem_t *sem_open(const char *name, int oflag, ... /* mode_t, unsigned */)
#[no_mangle]
pub unsafe extern "C" fn sem_open(name: *const u8, oflag: i32, mut args: ...) -> *mut sem_t {
    // SAFETY: name is a NUL-terminated C string; build_path scans it within
    // bounds. The varargs (mode_t, unsigned value) are present only when
    // O_CREAT is set, exactly as the POSIX sem_open contract guarantees, so we
    // read them only in that branch. Mapped file is validated kernel-side.
    unsafe {
        let mut buf = [0u8; PATH_CAP];
        match build_path(name, b"sem.", &mut buf) {
            Err(e) => { set(e); return SEM_FAILED; }
            Ok(_) => {}
        }
        let (mode, value) = if oflag & O_CREAT != 0 {
            let m = args.next_arg::<u32>();
            let v = args.next_arg::<u32>();
            (m, v)
        } else { (0u32, 0u32) };
        let fd = openat(AT_FDCWD, buf.as_ptr(), oflag | O_RDWR | O_CLOEXEC, mode);
        if fd < 0 { return SEM_FAILED; }
        // Size the backing object to one sem_t (ftruncate is idempotent; a
        // pre-existing file from a non-exclusive open keeps its contents).
        let created = oflag & O_CREAT != 0;
        if created { crate::posix::fs::ftruncate(fd, SEM_T_SZ as i64); }
        let p = mmap(core::ptr::null_mut(), SEM_T_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        crate::posix::io::close(fd);
        if p == MAP_FAILED { return SEM_FAILED; }
        // On a fresh create (not O_EXCL re-open) initialize the value word.
        if created && oflag & O_EXCL != 0 {
            (*(p as *const AtomicU32)).store(value, Ordering::Release);
        } else if created {
            // Non-exclusive create: initialize only when the word is still the
            // zero a fresh ftruncate left (a benign best-effort, matching the
            // single-opener conformance use).
            let w = &*(p as *const AtomicU32);
            let _ = w.compare_exchange(0, value, Ordering::AcqRel, Ordering::Acquire);
        }
        p as *mut sem_t
    }
}

// # C: int sem_close(sem_t *sem)
#[no_mangle]
pub unsafe extern "C" fn sem_close(sem: *mut sem_t) -> i32 {
    // SAFETY: sem is a pointer returned by sem_open (a SEM_T_SZ mapping);
    // unmapping it releases this process's reference. munmap validates the
    // range kernel-side.
    unsafe { munmap(sem as *mut u8, SEM_T_SZ) }
}

// # C: int sem_unlink(const char *name)
#[no_mangle]
pub unsafe extern "C" fn sem_unlink(name: *const u8) -> i32 {
    // SAFETY: name is a NUL-terminated C string; build_path scans within bounds
    // and the composed "/dev/shm/sem.<name>" path is unlinked via fs::unlink,
    // validated kernel-side.
    unsafe {
        let mut buf = [0u8; PATH_CAP];
        match build_path(name, b"sem.", &mut buf) {
            Err(e) => { set(e); -1 }
            Ok(_) => crate::posix::fs::unlink(buf.as_ptr()),
        }
    }
}
