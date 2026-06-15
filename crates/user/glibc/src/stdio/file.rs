// FILE (_IO_FILE) — glibc-ABI byte-compatible layout (docs/59§6 G6, §2).
// Pre-compiled Fedora binaries inline glibc's getc/putc/feof macros that
// poke these exact offsets, so the layout must match (sizeof 216, LP64,
// same on x86_64 + aarch64). G6a populates only _fileno/_flags for the
// std streams and does unbuffered I/O via the function entry points;
// buffer pointers + __overflow/__uflow (putc/getc macro compat) are a
// G6 follow-up. Layout recorded in abi/<arch>.toml.
//
// The FILE struct + its ABI layout test are always built (oracle); the
// std-stream statics + #[no_mangle] exports are freestanding-only.

pub const IO_EOF_SEEN: i32 = 0x10;
pub const IO_ERR_SEEN: i32 = 0x20;

#[repr(C)]
pub struct FILE {
    pub _flags: i32,
    _io_read_ptr: *mut u8,
    _io_read_end: *mut u8,
    _io_read_base: *mut u8,
    _io_write_base: *mut u8,
    _io_write_ptr: *mut u8,
    _io_write_end: *mut u8,
    _io_buf_base: *mut u8,
    _io_buf_end: *mut u8,
    _io_save_base: *mut u8,
    _io_backup_base: *mut u8,
    _io_save_end: *mut u8,
    _markers: *mut u8,
    _chain: *mut FILE,
    pub _fileno: i32,
    _flags2: i32,
    _old_offset: i64,
    _cur_column: u16,
    _vtable_offset: i8,
    _shortbuf: [u8; 1],
    _lock: *mut u8,
    _offset: i64,
    _codecvt: *mut u8,
    _wide_data: *mut u8,
    _freeres_list: *mut FILE,
    _freeres_buf: *mut u8,
    __pad5: usize,
    _mode: i32,
    _unused2: [u8; 20],
}

impl FILE {
    const fn std(fd: i32, flags: i32) -> FILE {
        FILE {
            _flags: flags, _io_read_ptr: core::ptr::null_mut(), _io_read_end: core::ptr::null_mut(),
            _io_read_base: core::ptr::null_mut(), _io_write_base: core::ptr::null_mut(),
            _io_write_ptr: core::ptr::null_mut(), _io_write_end: core::ptr::null_mut(),
            _io_buf_base: core::ptr::null_mut(), _io_buf_end: core::ptr::null_mut(),
            _io_save_base: core::ptr::null_mut(), _io_backup_base: core::ptr::null_mut(),
            _io_save_end: core::ptr::null_mut(), _markers: core::ptr::null_mut(), _chain: core::ptr::null_mut(),
            _fileno: fd, _flags2: 0, _old_offset: -1, _cur_column: 0, _vtable_offset: 0, _shortbuf: [0],
            _lock: core::ptr::null_mut(), _offset: -1, _codecvt: core::ptr::null_mut(),
            _wide_data: core::ptr::null_mut(), _freeres_list: core::ptr::null_mut(),
            _freeres_buf: core::ptr::null_mut(), __pad5: 0, _mode: 0, _unused2: [0; 20],
        }
    }
}

pub(crate) unsafe fn fd_of(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid FILE pointer; we read its _fileno field.
    unsafe { (*f)._fileno }
}

// Non-fd streams have _fileno == -1 and a cookie pointer in the otherwise-unused
// _codecvt field. _flags2 bit 1 (IS_COOKIE) tells fopencookie streams apart from
// fmemopen/open_memstream memory streams.
const IS_COOKIE: i32 = 2;
pub(crate) unsafe fn is_mem(f: *mut FILE) -> bool {
    // SAFETY: f is a valid FILE; an fd-less stream without the cookie bit is a
    // fmemopen/open_memstream memory stream.
    unsafe { (*f)._fileno < 0 && (*f)._flags2 & IS_COOKIE == 0 }
}
pub(crate) unsafe fn is_cookie(f: *mut FILE) -> bool {
    // SAFETY: f is a valid FILE; an fd-less stream with the cookie bit set is a
    // fopencookie custom-callback stream.
    unsafe { (*f)._fileno < 0 && (*f)._flags2 & IS_COOKIE != 0 }
}
pub(crate) unsafe fn set_cookie(f: *mut FILE, c: *mut u8) {
    // SAFETY: f is a valid FILE; repurpose _codecvt (unused: no wide I/O) to
    // hold the memory-stream cookie pointer, and mark the stream fd-less.
    unsafe { (*f)._codecvt = c; (*f)._fileno = -1; }
}
pub(crate) unsafe fn set_cookie_backing(f: *mut FILE, c: *mut u8) {
    // SAFETY: as set_cookie, plus the IS_COOKIE bit for a fopencookie stream.
    unsafe { (*f)._codecvt = c; (*f)._fileno = -1; (*f)._flags2 |= IS_COOKIE; }
}
pub(crate) unsafe fn cookie(f: *mut FILE) -> *mut u8 {
    // SAFETY: f is a valid memory/cookie stream; read the cookie pointer back.
    unsafe { (*f)._codecvt }
}

#[cfg(feature = "freestanding")]
pub(crate) use streams::{alloc_file, free_file, is_std, set_eof, set_unget, stdin_ptr, stdout_ptr, take_unget};

#[cfg(feature = "freestanding")]
mod streams {
    use super::{FILE, IO_EOF_SEEN, IO_ERR_SEEN};
    use core::cell::UnsafeCell;

    struct StdFile(UnsafeCell<FILE>);
    // SAFETY: the std-stream FILE objects are process-global; mutation (G6b
    // buffering) will be guarded then. G6a only reads _fileno/_flags.
    unsafe impl Sync for StdFile {}

    static STDIN_FILE: StdFile = StdFile(UnsafeCell::new(FILE::std(0, 0)));
    static STDOUT_FILE: StdFile = StdFile(UnsafeCell::new(FILE::std(1, 0)));
    static STDERR_FILE: StdFile = StdFile(UnsafeCell::new(FILE::std(2, 0)));

    #[repr(transparent)]
    struct FilePtr(*mut FILE);
    // SAFETY: holds a stable pointer to a 'static StdFile; never freed.
    unsafe impl Sync for FilePtr {}

    // # C: extern FILE *stdin/stdout/stderr;
    #[no_mangle]
    static stdin: FilePtr = FilePtr(STDIN_FILE.0.get());
    #[no_mangle]
    static stdout: FilePtr = FilePtr(STDOUT_FILE.0.get());
    #[no_mangle]
    static stderr: FilePtr = FilePtr(STDERR_FILE.0.get());

    /// # C: &stdout
    pub(crate) fn stdout_ptr() -> *mut FILE { STDOUT_FILE.0.get() }
    /// # C: &stderr
    pub(crate) fn stderr_ptr() -> *mut FILE { STDERR_FILE.0.get() }
    /// # C: &stdin
    pub(crate) fn stdin_ptr() -> *mut FILE { STDIN_FILE.0.get() }

    /// # C: stream is one of stdin/stdout/stderr
    pub(crate) fn is_std(f: *mut FILE) -> bool {
        f == STDIN_FILE.0.get() || f == STDOUT_FILE.0.get() || f == STDERR_FILE.0.get()
    }

    // _flags2 bit 0 = a pushed-back byte sits in _shortbuf[0] (our one-char
    // ungetc; glibc uses _IO_backup_base, but we own these FILE objects).
    const HAS_UNGET: i32 = 1;
    pub(crate) unsafe fn alloc_file(fd: i32, flags: i32) -> *mut FILE {
        // SAFETY: allocate a FILE on the heap and initialise every field
        // via FILE::std; returns null on OOM.
        unsafe {
            let p = crate::malloc::heap::malloc(core::mem::size_of::<FILE>()) as *mut FILE;
            if !p.is_null() { p.write(FILE::std(fd, flags)); }
            p
        }
    }
    pub(crate) unsafe fn free_file(f: *mut FILE) {
        // SAFETY: f was returned by alloc_file (a heap FILE), not a std stream.
        unsafe { crate::malloc::heap::free(f as *mut u8); }
    }
    pub(crate) unsafe fn set_eof(f: *mut FILE) {
        // SAFETY: f is a valid stream; set its EOF flag bit.
        unsafe { (*f)._flags |= IO_EOF_SEEN; }
    }
    pub(crate) unsafe fn set_unget(f: *mut FILE, c: u8) {
        // SAFETY: f is a valid stream; stash one pushed-back byte.
        unsafe { (*f)._flags2 |= HAS_UNGET; (*f)._shortbuf[0] = c; }
    }
    pub(crate) unsafe fn take_unget(f: *mut FILE) -> Option<u8> {
        // SAFETY: f is a valid stream; consume any pushed-back byte.
        unsafe {
            if (*f)._flags2 & HAS_UNGET != 0 { (*f)._flags2 &= !HAS_UNGET; Some((*f)._shortbuf[0]) } else { None }
        }
    }

    // # C: int fileno(FILE *)
    #[no_mangle]
    pub unsafe extern "C" fn fileno(f: *mut FILE) -> i32 {
        // SAFETY: f is a valid open stream per the C contract.
        unsafe { (*f)._fileno }
    }
    // # C: int feof(FILE *)
    #[no_mangle]
    pub unsafe extern "C" fn feof(f: *mut FILE) -> i32 {
        // SAFETY: f is a valid stream; read its EOF flag bit.
        unsafe { ((*f)._flags & IO_EOF_SEEN != 0) as i32 }
    }
    // # C: int ferror(FILE *)
    #[no_mangle]
    pub unsafe extern "C" fn ferror(f: *mut FILE) -> i32 {
        // SAFETY: f is a valid stream; read its error flag bit.
        unsafe { ((*f)._flags & IO_ERR_SEEN != 0) as i32 }
    }
    // # C: void clearerr(FILE *)
    #[no_mangle]
    pub unsafe extern "C" fn clearerr(f: *mut FILE) {
        // SAFETY: f is a valid stream; clear its EOF+error flag bits.
        unsafe { (*f)._flags &= !(IO_EOF_SEEN | IO_ERR_SEEN); }
    }
}

#[cfg(test)]
mod tests {
    use super::FILE;
    #[test]
    fn file_abi_layout() {
        // glibc _IO_FILE LP64 golden offsets/size (abi/<arch>.toml).
        assert_eq!(core::mem::size_of::<FILE>(), 216);
        assert_eq!(core::mem::offset_of!(FILE, _flags), 0);
        assert_eq!(core::mem::offset_of!(FILE, _io_write_ptr), 40);
        assert_eq!(core::mem::offset_of!(FILE, _io_write_end), 48);
        assert_eq!(core::mem::offset_of!(FILE, _fileno), 112);
    }
}
