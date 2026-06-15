// stdio *_unlocked variants + file locking (docs/59§6 G6). We are
// single-threaded (no FILE locks yet), so every *_unlocked function is an
// exact alias of its locked counterpart and flockfile/funlockfile are no-ops.
// C ABI only.
#![cfg(feature = "freestanding")]
use super::file::FILE;
use core::ffi::c_void;

extern "C" {
    fn getc(f: *mut FILE) -> i32;
    fn putc(c: i32, f: *mut FILE) -> i32;
    fn getchar() -> i32;
    fn putchar(c: i32) -> i32;
    fn fgetc(f: *mut FILE) -> i32;
    fn fputc(c: i32, f: *mut FILE) -> i32;
    fn fread(p: *mut u8, sz: usize, n: usize, f: *mut FILE) -> usize;
    fn fwrite(p: *const u8, sz: usize, n: usize, f: *mut FILE) -> usize;
    fn fgets(b: *mut u8, n: i32, f: *mut FILE) -> *mut u8;
    fn fputs(s: *const u8, f: *mut FILE) -> i32;
    fn fflush(f: *mut FILE) -> i32;
    fn feof(f: *mut FILE) -> i32;
    fn ferror(f: *mut FILE) -> i32;
    fn clearerr(f: *mut FILE);
    fn fileno(f: *mut FILE) -> i32;
}

macro_rules! alias {
    ($(#[$m:meta])* $u:ident ($($a:ident : $t:ty),*) -> $r:ty = $base:ident) => {
        $(#[$m])*
        #[no_mangle] pub unsafe extern "C" fn $u($($a: $t),*) -> $r {
            // SAFETY: single-threaded → identical to the locked $base; forwards.
            unsafe { $base($($a),*) }
        }
    };
}

alias!(/// # C: int getc_unlocked(FILE *)
       getc_unlocked(f: *mut FILE) -> i32 = getc);
alias!(/// # C: int putc_unlocked(int, FILE *)
       putc_unlocked(c: i32, f: *mut FILE) -> i32 = putc);
alias!(/// # C: int getchar_unlocked(void)
       getchar_unlocked() -> i32 = getchar);
alias!(/// # C: int putchar_unlocked(int)
       putchar_unlocked(c: i32) -> i32 = putchar);
alias!(/// # C: int fgetc_unlocked(FILE *)
       fgetc_unlocked(f: *mut FILE) -> i32 = fgetc);
alias!(/// # C: int fputc_unlocked(int, FILE *)
       fputc_unlocked(c: i32, f: *mut FILE) -> i32 = fputc);
alias!(/// # C: size_t fread_unlocked(void *, size_t, size_t, FILE *)
       fread_unlocked(p: *mut u8, sz: usize, n: usize, f: *mut FILE) -> usize = fread);
alias!(/// # C: size_t fwrite_unlocked(const void *, size_t, size_t, FILE *)
       fwrite_unlocked(p: *const u8, sz: usize, n: usize, f: *mut FILE) -> usize = fwrite);
alias!(/// # C: char *fgets_unlocked(char *, int, FILE *)
       fgets_unlocked(b: *mut u8, n: i32, f: *mut FILE) -> *mut u8 = fgets);
alias!(/// # C: int fputs_unlocked(const char *, FILE *)
       fputs_unlocked(s: *const u8, f: *mut FILE) -> i32 = fputs);
alias!(/// # C: int fflush_unlocked(FILE *)
       fflush_unlocked(f: *mut FILE) -> i32 = fflush);
alias!(/// # C: int feof_unlocked(FILE *)
       feof_unlocked(f: *mut FILE) -> i32 = feof);
alias!(/// # C: int ferror_unlocked(FILE *)
       ferror_unlocked(f: *mut FILE) -> i32 = ferror);
alias!(/// # C: int fileno_unlocked(FILE *)
       fileno_unlocked(f: *mut FILE) -> i32 = fileno);

// # C: void clearerr_unlocked(FILE *)
#[no_mangle]
pub unsafe extern "C" fn clearerr_unlocked(f: *mut FILE) {
    // SAFETY: single-threaded → identical to clearerr.
    unsafe { clearerr(f) }
}

// File locking — no-ops (no FILE locks until threading hardening).
// # C: void flockfile(FILE *)
#[no_mangle]
pub extern "C" fn flockfile(_f: *mut c_void) {}
// # C: void funlockfile(FILE *)
#[no_mangle]
pub extern "C" fn funlockfile(_f: *mut c_void) {}
// # C: int ftrylockfile(FILE *) — 0 = lock acquired
#[no_mangle]
pub extern "C" fn ftrylockfile(_f: *mut c_void) -> i32 { 0 }
