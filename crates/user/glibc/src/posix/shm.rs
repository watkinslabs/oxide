// POSIX shared memory <sys/mman.h> shm_open/shm_unlink (docs/59§6). A POSIX
// shm object is a file under /dev/shm: shm_open opens (with O_NOFOLLOW |
// O_CLOEXEC forced on, per glibc) a path "/dev/shm/<name>"; the returned fd is
// usable with ftruncate + mmap. shm_unlink removes that file. The name must
// start with '/' and contain no other '/' (glibc rejects otherwise — EINVAL).
#![cfg(feature = "freestanding")]
use crate::internal::errno::set;
use crate::posix::io::{openat, AT_FDCWD, O_CLOEXEC};

const EINVAL: i32 = 22;
const ENAMETOOLONG: i32 = 36;
// O_NOFOLLOW (asm-generic/fcntl.h) — same value both arches; not exported by
// io.rs, defined here for the shm path which glibc opens with it.
const O_NOFOLLOW: i32 = 0o400000;
// /dev/shm prefix + room for the validated name (glibc uses NAME_MAX).
const SHM_DIR: &[u8] = b"/dev/shm/";
const NAME_MAX: usize = 255;
pub(crate) const PATH_CAP: usize = SHM_DIR.len() + NAME_MAX + 1;

// Validate a POSIX shm/sem name and build "/dev/shm/<name>" into `out` (NUL-
// terminated). Returns the byte length written (excluding NUL), or an errno on
// failure. glibc strips the single leading '/'; embedded '/' → EINVAL.
pub(crate) unsafe fn build_path(name: *const u8, prefix: &[u8], out: &mut [u8; PATH_CAP]) -> Result<usize, i32> {
    // SAFETY: name is a caller-supplied NUL-terminated C string per the POSIX
    // contract; we scan it bytewise up to NAME_MAX, never past its terminator.
    unsafe {
        if name.is_null() { return Err(EINVAL); }
        // Skip the mandatory single leading '/'.
        let mut p = name;
        if *p != b'/' { return Err(EINVAL); }
        p = p.add(1);
        let mut i = 0usize;
        for d in SHM_DIR { out[i] = *d; i += 1; }
        for d in prefix { out[i] = *d; i += 1; }
        let mut n = 0usize;
        loop {
            let c = *p.add(n);
            if c == 0 { break; }
            if c == b'/' { return Err(EINVAL); }   // embedded slash invalid
            n += 1;
            if n > NAME_MAX { return Err(ENAMETOOLONG); }
            if i >= PATH_CAP - 1 { return Err(ENAMETOOLONG); }
            out[i] = c; i += 1;
        }
        if n == 0 { return Err(EINVAL); }          // empty after the slash
        out[i] = 0;
        Ok(i)
    }
}

// # C: int shm_open(const char *name, int oflag, mode_t mode)
#[no_mangle]
pub unsafe extern "C" fn shm_open(name: *const u8, oflag: i32, mode: u32) -> i32 {
    // SAFETY: name is a NUL-terminated C string; build_path scans it within
    // bounds and never dereferences past its terminator. The composed path is
    // a local buffer passed to openat, which validates it kernel-side.
    unsafe {
        let mut buf = [0u8; PATH_CAP];
        match build_path(name, b"", &mut buf) {
            Err(e) => { set(e); -1 }
            Ok(_) => openat(AT_FDCWD, buf.as_ptr(), oflag | O_NOFOLLOW | O_CLOEXEC, mode),
        }
    }
}

// # C: int shm_unlink(const char *name)
#[no_mangle]
pub unsafe extern "C" fn shm_unlink(name: *const u8) -> i32 {
    // SAFETY: name is a NUL-terminated C string; build_path scans within bounds
    // and the composed path is unlinked via the io::unlink wrapper, which the
    // kernel validates.
    unsafe {
        let mut buf = [0u8; PATH_CAP];
        match build_path(name, b"", &mut buf) {
            Err(e) => { set(e); -1 }
            Ok(_) => crate::posix::fs::unlink(buf.as_ptr()),
        }
    }
}
