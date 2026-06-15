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

// glibc fpos_t / fpos64_t (_G_fpos{,64}_t): { __off_t __pos; __mbstate_t
// __state; } = 16 bytes on LP64. fgetpos/fsetpos use only __pos (narrow
// streams keep a zero mbstate). Layout is ABI-fixed; tested below.
#[repr(C)]
pub struct Fpos { pub __pos: i64, pub __state: [u8; 8] }

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

// glibc _flags buffering bits (introspection + setvbuf record intent; the
// actual I/O path is unbuffered, so these are advisory but ABI-visible).
pub const IO_UNBUFFERED: i32 = 0x0002;
pub const IO_LINE_BUF: i32 = 0x0200;
// glibc access-mode + last-op flags: NO_READS/NO_WRITES mark the stream's
// mode, CURRENTLY_PUTTING records that the last op was a write.
pub const IO_NO_READS: i32 = 0x0004;
pub const IO_NO_WRITES: i32 = 0x0008;
pub const IO_CURRENTLY_PUTTING: i32 = 0x0800;

#[cfg(feature = "freestanding")]
pub(crate) use streams::{alloc_file, free_file, is_std, set_eof, set_unget, stdin_ptr, stdout_ptr,
    take_unget, get_orient, set_orient, set_wunget, take_wunget,
    set_buf, buf_size, set_bufmode, last_was_read, mark_read, mark_write,
    set_popen_pid, popen_pid};

#[cfg(feature = "freestanding")]
mod streams {
    use super::{FILE, IO_EOF_SEEN, IO_ERR_SEEN, IO_UNBUFFERED, IO_LINE_BUF, IO_CURRENTLY_PUTTING};
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

    // Stream orientation (C99 7.19.2): _mode < 0 byte/narrow, > 0 wide, 0 unset.
    // glibc uses this exact _IO_FILE._mode field for the same purpose.
    pub(crate) unsafe fn get_orient(f: *mut FILE) -> i32 {
        // SAFETY: f is a valid stream; read its orientation field.
        unsafe { (*f)._mode }
    }
    pub(crate) unsafe fn set_orient(f: *mut FILE, mode: i32) {
        // SAFETY: f is a valid stream; record orientation only when still
        // unset (0), per C99 — the first wide/narrow op fixes it.
        unsafe { if (*f)._mode == 0 { (*f)._mode = mode; } }
    }

    // _flags2 bit 2 = a pushed-back wide char sits in _wide_data (reinterpreted
    // as the wchar_t value). One-char ungetwc, mirroring the narrow pushback.
    const HAS_WUNGET: i32 = 4;
    pub(crate) unsafe fn set_wunget(f: *mut FILE, wc: i32) {
        // SAFETY: f is a valid stream; stash one pushed-back wide char in the
        // otherwise-unused _wide_data field (we do no glibc wide-buffer I/O).
        unsafe { (*f)._flags2 |= HAS_WUNGET; (*f)._wide_data = wc as usize as *mut u8; }
    }
    pub(crate) unsafe fn take_wunget(f: *mut FILE) -> Option<i32> {
        // SAFETY: f is a valid stream; consume any pushed-back wide char.
        unsafe {
            if (*f)._flags2 & HAS_WUNGET != 0 { (*f)._flags2 &= !HAS_WUNGET; Some((*f)._wide_data as usize as i32) } else { None }
        }
    }

    // setvbuf records the caller's buffer + capacity in the glibc buffer-pointer
    // fields so the GNU introspection (__fbufsize) can report them. Our I/O is
    // unbuffered, so the buffer is advisory; the ABI fields stay consistent.
    pub(crate) unsafe fn set_buf(f: *mut FILE, base: *mut u8, size: usize) {
        // SAFETY: f is a valid stream; record an advisory user buffer in the
        // glibc _io_buf_base/_io_buf_end pointer pair (size bytes wide).
        unsafe { (*f)._io_buf_base = base; (*f)._io_buf_end = if base.is_null() { core::ptr::null_mut() } else { base.add(size) }; }
    }
    pub(crate) unsafe fn buf_size(f: *mut FILE) -> usize {
        // SAFETY: f is a valid stream; the buffer span is end-base (0 if unset).
        unsafe {
            let (b, e) = ((*f)._io_buf_base, (*f)._io_buf_end);
            if b.is_null() || e.is_null() { 0 } else { (e as usize).wrapping_sub(b as usize) }
        }
    }
    pub(crate) unsafe fn set_bufmode(f: *mut FILE, mode: i32) {
        // SAFETY: f is a valid stream; clear the two buffering bits then set the
        // one for `mode` (0=_IOFBF full, 1=_IOLBF line, 2=_IONBF none).
        unsafe {
            (*f)._flags &= !(IO_UNBUFFERED | IO_LINE_BUF);
            match mode { 1 => (*f)._flags |= IO_LINE_BUF, 2 => (*f)._flags |= IO_UNBUFFERED, _ => {} }
        }
    }
    // Track last-op direction for __freading/__fwriting via CURRENTLY_PUTTING.
    pub(crate) unsafe fn mark_read(f: *mut FILE) {
        // SAFETY: f is a valid stream; clear the write-in-progress flag.
        unsafe { (*f)._flags &= !IO_CURRENTLY_PUTTING; }
    }
    pub(crate) unsafe fn mark_write(f: *mut FILE) {
        // SAFETY: f is a valid stream; set the write-in-progress flag.
        unsafe { (*f)._flags |= IO_CURRENTLY_PUTTING; }
    }
    pub(crate) unsafe fn last_was_read(f: *mut FILE) -> bool {
        // SAFETY: f is a valid stream; the put flag being clear means the last
        // direction was a read.
        unsafe { (*f)._flags & IO_CURRENTLY_PUTTING == 0 }
    }

    // popen stores the child pid in the otherwise-unused _old_offset field so
    // pclose can waitpid on it. 0 = not a popen stream.
    pub(crate) unsafe fn set_popen_pid(f: *mut FILE, pid: i32) {
        // SAFETY: f is a fresh popen stream; stash the child pid for pclose.
        unsafe { (*f)._old_offset = pid as i64; }
    }
    pub(crate) unsafe fn popen_pid(f: *mut FILE) -> i32 {
        // SAFETY: f is a valid stream; read back any popen child pid.
        unsafe { (*f)._old_offset as i32 }
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
    use super::{Fpos, FILE};
    #[test]
    fn fpos_abi_layout() {
        // glibc _G_fpos64_t: __off64_t (8) + __mbstate_t (8) = 16 bytes.
        assert_eq!(core::mem::size_of::<Fpos>(), 16);
        assert_eq!(core::mem::offset_of!(Fpos, __pos), 0);
    }
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
