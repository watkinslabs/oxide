// mkstemp(3) family (docs/59§6 G7). Replace the trailing "XXXXXX" of
// `template` with base-62 letters drawn from getrandom(2) and
// open(O_RDWR|O_CREAT|O_EXCL, 0600), retrying on collision. Name generation
// and the retry loop live in `super::tempname` (glibc
// sysdeps/posix/tempname.c `try_tempname_len`), shared with mkdtemp/mktemp.
// C ABI only.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::sys4;
use crate::internal::nr;
use crate::stdlib::tempname::gen::try_tempname;

const AT_FDCWD: usize = (-100i64) as usize;
const O_RDWR: usize = 2;
const O_CREAT: usize = 0o100;
const O_EXCL: usize = 0o200;
const O_ACCMODE: usize = 0o3;
// glibc try_file(): S_IRUSR|S_IWUSR.
const TEMPFILE_MODE: usize = 0o600;

// glibc try_file(): (*openflags & ~O_ACCMODE) | O_RDWR | O_CREAT | O_EXCL.
// O_CREAT|O_EXCL are always ours, so the caller cannot weaken the atomic
// create that makes the temp name safe.
fn open_flags(extra: usize) -> usize { (extra & !(O_ACCMODE | O_CREAT | O_EXCL)) | O_RDWR | O_CREAT | O_EXCL }

// Fill the "XXXXXX" run that sits suffixlen bytes before the end and openat
// the result. suffixlen = chars after "XXXXXX" (mkstemps).
unsafe fn do_mkstemp(template: *mut u8, extra: usize, suffixlen: usize) -> i32 {
    let flags = open_flags(extra);
    let try_file = |t: *mut u8| {
        // SAFETY: openat(2) on the freshly rewritten template, a NUL-terminated
        // path owned by the caller; O_EXCL makes the create-or-EEXIST decision
        // atomic in the kernel, which is what makes the temp name race-free.
        unsafe { sys4(nr::OPENAT, AT_FDCWD, t as usize, flags, TEMPFILE_MODE) }
    };
    // SAFETY: template is a writable C string ending in "XXXXXX" plus suffixlen
    // trailing bytes; try_tempname validates that run before rewriting it.
    unsafe { try_tempname(template, suffixlen, try_file) as i32 }
}

// # C: int mkstemp(char *template)
#[no_mangle]
pub unsafe extern "C" fn mkstemp(template: *mut u8) -> i32 {
    // SAFETY: template ends in "XXXXXX"; do_mkstemp overwrites them + opens.
    unsafe { do_mkstemp(template, 0, 0) }
}

// # C: int mkostemp(char *template, int flags) — mkstemp + extra open flags.
#[no_mangle]
pub unsafe extern "C" fn mkostemp(template: *mut u8, flags: i32) -> i32 {
    // SAFETY: template ends in "XXXXXX"; do_mkstemp overwrites them + opens with
    // the extra (masked) flags OR'd into the openat call.
    unsafe { do_mkstemp(template, flags as usize, 0) }
}

// # C: int mkstemps(char *template, int suffixlen) — "XXXXXX<suffix>".
#[no_mangle]
pub unsafe extern "C" fn mkstemps(template: *mut u8, suffixlen: i32) -> i32 {
    // SAFETY: as mkstemp with a fixed suffix after the X's.
    unsafe { do_mkstemp(template, 0, suffixlen.max(0) as usize) }
}

// # C: int mkostemps(char *template, int suffixlen, int flags) — mkstemps + flags.
#[no_mangle]
pub unsafe extern "C" fn mkostemps(template: *mut u8, suffixlen: i32, flags: i32) -> i32 {
    // SAFETY: "XXXXXX<suffix>"; do_mkstemp overwrites the X's + opens with the
    // extra (masked) flags.
    unsafe { do_mkstemp(template, flags as usize, suffixlen.max(0) as usize) }
}

// LFS aliases — identical on LP64 (off64_t == off_t; the temp path is the same).
// SAFETY: mkstemp64 == mkstemp on LP64; template ends in the "XXXXXX" run.
#[no_mangle] pub unsafe extern "C" fn mkstemp64(t: *mut u8) -> i32 { unsafe { mkstemp(t) } }
// SAFETY: mkstemps64 == mkstemps on LP64; "XXXXXX<suffix>" template.
#[no_mangle] pub unsafe extern "C" fn mkstemps64(t: *mut u8, s: i32) -> i32 { unsafe { mkstemps(t, s) } }
// SAFETY: mkostemp64 == mkostemp on LP64; template + extra open flags.
#[no_mangle] pub unsafe extern "C" fn mkostemp64(t: *mut u8, f: i32) -> i32 { unsafe { mkostemp(t, f) } }
// SAFETY: mkostemps64 == mkostemps on LP64; suffix + extra open flags.
#[no_mangle] pub unsafe extern "C" fn mkostemps64(t: *mut u8, s: i32, f: i32) -> i32 { unsafe { mkostemps(t, s, f) } }
