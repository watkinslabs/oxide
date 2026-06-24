// In-memory streams (docs/59§6 G6): fmemopen + open_memstream. A memory stream
// is a FILE with _fileno = -1 and a MemCookie* in _codecvt (file.rs). The
// stream_{read,write,seek,tell} helpers below are the choke points the rest of
// stdio routes through, so fread/fwrite/fseek/getc/fputs all work unchanged on
// memory streams. C ABI only.
#![cfg(feature = "freestanding")]
use super::cookie::{cookie_read, cookie_seek, cookie_write};
use super::file::{alloc_file, cookie, fd_of, is_cookie, is_mem, set_cookie, FILE};
use crate::malloc::heap;
use crate::posix::io;

const EINVAL: i32 = 22;

pub(crate) struct MemCookie {
    buf: *mut u8,
    pos: usize,
    len: usize,  // logical length: readable extent / write high-water mark
    term: usize, // terminator slot; differs from len for open_wmemstream seek-back writes
    cap: usize,  // allocated capacity (fmemopen: fixed = size; memstream grows)
    readable: bool,
    writable: bool,
    nul_term: bool,        // keep a NUL just past the data (w/a fmemopen, memstream)
    dynamic: bool,         // open_memstream: realloc-grow + publish to user ptrs
    wide: bool,            // open_wmemstream: buf/pos/len/cap are wchar_t units
    own_buf: bool,         // free buf on close (fmemopen NULL-buf, memstream)
    uptr: *mut *mut u8,    // open_memstream: *uptr = buf
    usz: *mut usize,       // open_memstream: *usz = len
}

unsafe fn ck(f: *mut FILE) -> *mut MemCookie {
    // SAFETY: f is a memory stream; its cookie pointer lives in _codecvt.
    unsafe { cookie(f) as *mut MemCookie }
}

// publish the current buffer + length to an open_memstream caller and keep the
// trailing NUL in place.
unsafe fn publish(c: *mut MemCookie) {
    // SAFETY: c is a live cookie; for dynamic streams uptr/usz are the caller's
    // out-params and buf has room for the terminator (ensured on every write).
    unsafe {
        if (*c).nul_term && (*c).len < (*c).cap {
            if (*c).wide {
                if (*c).term < (*c).cap { *((*c).buf as *mut i32).add((*c).term) = 0; }
            } else {
                *(*c).buf.add((*c).len) = 0;
            }
        }
        if (*c).dynamic {
            if !(*c).uptr.is_null() { *(*c).uptr = (*c).buf; }
            if !(*c).usz.is_null() { *(*c).usz = (*c).len; }
        }
    }
}

unsafe fn grow(c: *mut MemCookie, need: usize) -> bool {
    // SAFETY: c is a live dynamic cookie; realloc buf to hold `need` elements
    // plus the always-present terminator, doubling to amortise.
    unsafe {
        if need < (*c).cap { return true; } // room for need elements + the NUL
        let mut nc = if (*c).cap == 0 { 64 } else { (*c).cap };
        while nc < need + 1 { nc *= 2; }
        let elem = if (*c).wide { core::mem::size_of::<i32>() } else { 1 };
        let nb = heap::realloc((*c).buf, nc * elem);
        if nb.is_null() { return false; }
        (*c).buf = nb; (*c).cap = nc; true
    }
}

pub(crate) unsafe fn mem_read(f: *mut FILE, dst: *mut u8, n: usize) -> isize {
    // SAFETY: f is a readable memory stream; copy up to min(n, len-pos) bytes.
    unsafe {
        let c = ck(f);
        if !(*c).readable { return 0; }
        if (*c).wide { return 0; }
        let avail = (*c).len.saturating_sub((*c).pos);
        let r = n.min(avail);
        if r > 0 { core::ptr::copy_nonoverlapping((*c).buf.add((*c).pos), dst, r); (*c).pos += r; }
        r as isize
    }
}

pub(crate) unsafe fn mem_write(f: *mut FILE, src: *const u8, n: usize) -> isize {
    // SAFETY: f is a writable memory stream; fmemopen writes only what fits in
    // the fixed buffer (short write at the end), open_memstream grows.
    unsafe {
        let c = ck(f);
        if !(*c).writable || n == 0 { return 0; }
        if (*c).wide { return 0; }
        let w = if (*c).dynamic {
            if !grow(c, (*c).pos + n) { return 0; }
            n
        } else {
            // fmemopen: bounded by the fixed size; the position may advance to
            // `cap`, and the trailing NUL then stomps the last data byte (glibc).
            n.min((*c).cap.saturating_sub((*c).pos))
        };
        if w > 0 { core::ptr::copy_nonoverlapping(src, (*c).buf.add((*c).pos), w); (*c).pos += w; }
        if (*c).pos > (*c).len { (*c).len = (*c).pos; }
        (*c).term = (*c).len;
        if (*c).nul_term {
            // NUL just past the data, or over the last byte when the buffer is full
            let np = if (*c).pos < (*c).cap { (*c).pos } else { (*c).cap - 1 };
            *(*c).buf.add(np) = 0;
        }
        if (*c).dynamic { publish(c); }
        w as isize
    }
}

pub(crate) unsafe fn mem_seek(f: *mut FILE, off: i64, whence: i32) -> i64 {
    // SAFETY: f is a memory stream; compute the new cursor from SET/CUR/END.
    unsafe {
        let c = ck(f);
        let base = match whence { x if x == io::SEEK_CUR => (*c).pos as i64, x if x == io::SEEK_END => (*c).len as i64, _ => 0 };
        let np = base + off;
        if np < 0 { return -1; }
        let np = np as usize;
        if !(*c).dynamic && np > (*c).cap { return -1; } // fmemopen: bounded by size
        (*c).pos = np;
        np as i64
    }
}

pub(crate) unsafe fn mem_tell(f: *mut FILE) -> i64 {
    // SAFETY: f is a memory stream; the cursor is its logical position.
    unsafe { (*ck(f)).pos as i64 }
}

// fflush on a memory stream republishes buffer/length (open_memstream contract).
pub(crate) unsafe fn mem_flush(f: *mut FILE) {
    // SAFETY: f is a memory stream with a live cookie.
    unsafe { publish(ck(f)); }
}

pub(crate) unsafe fn wmem_write(f: *mut FILE, wc: i32) -> Option<bool> {
    // SAFETY: f is a memory stream; when it is an open_wmemstream, append one
    // wchar_t unit and republish the wchar buffer/length.
    unsafe {
        if !is_mem(f) { return None; }
        let c = ck(f);
        if !(*c).wide { return None; }
        if !(*c).writable { return Some(false); }
        if !grow(c, (*c).pos + 1) { return Some(false); }
        let wb = (*c).buf as *mut i32;
        *wb.add((*c).pos) = wc;
        (*c).pos += 1;
        (*c).len = (*c).pos;
        if (*c).pos > (*c).term { (*c).term = (*c).pos; }
        publish(c);
        Some(true)
    }
}

// fclose on a memory stream: finalize, then free the buffer (if owned) + cookie.
pub(crate) unsafe fn mem_close(f: *mut FILE) {
    // SAFETY: f is a memory stream; publish then release owned memory. For
    // open_memstream the buffer is handed to the caller (own_buf=false), so
    // only the cookie is freed.
    unsafe {
        let c = ck(f);
        publish(c);
        if (*c).own_buf && !(*c).dynamic { heap::free((*c).buf); }
        heap::free(c as *mut u8);
    }
}

unsafe fn new_cookie(c: MemCookie) -> *mut MemCookie {
    // SAFETY: allocate a cookie on the heap and move `c` into it.
    unsafe {
        let p = heap::malloc(core::mem::size_of::<MemCookie>()) as *mut MemCookie;
        if !p.is_null() { p.write(c); }
        p
    }
}

// # C: FILE *fmemopen(void *buf, size_t size, const char *mode)
#[no_mangle]
pub unsafe extern "C" fn fmemopen(buf: *mut u8, size: usize, mode: *const u8) -> *mut FILE {
    // SAFETY: buf is null or valid for `size` bytes; mode is a NUL-terminated
    // open mode. Builds a fixed-size memory stream per C/POSIX fmemopen.
    unsafe {
        if size == 0 || mode.is_null() { crate::internal::errno::set(EINVAL); return core::ptr::null_mut(); }
        let m0 = *mode;
        let mut plus = false;
        let mut i = 0; while *mode.add(i) != 0 { if *mode.add(i) == b'+' { plus = true; } i += 1; }
        let readable = m0 == b'r' || plus;
        let writable = m0 == b'w' || m0 == b'a' || plus;
        if !readable && !writable { crate::internal::errno::set(EINVAL); return core::ptr::null_mut(); }
        let (b, own) = if buf.is_null() {
            if !writable { crate::internal::errno::set(EINVAL); return core::ptr::null_mut(); }
            let nb = heap::malloc(size); if nb.is_null() { return core::ptr::null_mut(); }
            core::ptr::write_bytes(nb, 0, size); (nb, true)
        } else { (buf, false) };
        // initial position + logical length per mode
        let (pos, len) = match m0 {
            b'w' => { if writable { *b = 0; } (0, 0) }
            b'a' => { let mut k = 0; while k < size && *b.add(k) != 0 { k += 1; } (k, k) }
            _ => (0, size), // r / r+
        };
        let c = new_cookie(MemCookie {
            buf: b, pos, len, term: len, cap: size, readable, writable,
            nul_term: m0 == b'w' || m0 == b'a', dynamic: false, wide: false, own_buf: own,
            uptr: core::ptr::null_mut(), usz: core::ptr::null_mut(),
        });
        if c.is_null() { if own { heap::free(b); } return core::ptr::null_mut(); }
        let f = alloc_file(-1, 0);
        if f.is_null() { heap::free(c as *mut u8); if own { heap::free(b); } return core::ptr::null_mut(); }
        set_cookie(f, c as *mut u8);
        f
    }
}

// # C: FILE *open_memstream(char **ptr, size_t *sizeloc)
#[no_mangle]
pub unsafe extern "C" fn open_memstream(ptr: *mut *mut u8, sizeloc: *mut usize) -> *mut FILE {
    // SAFETY: ptr/sizeloc are writable out-params updated on flush/close; the
    // dynamically-grown buffer is handed to the caller, who frees it.
    unsafe {
        if ptr.is_null() || sizeloc.is_null() { crate::internal::errno::set(EINVAL); return core::ptr::null_mut(); }
        let b = heap::malloc(64); if b.is_null() { return core::ptr::null_mut(); }
        *b = 0;
        let c = new_cookie(MemCookie {
            buf: b, pos: 0, len: 0, term: 0, cap: 64, readable: false, writable: true,
            nul_term: true, dynamic: true, wide: false, own_buf: true, uptr: ptr, usz: sizeloc,
        });
        if c.is_null() { heap::free(b); return core::ptr::null_mut(); }
        let f = alloc_file(-1, 0);
        if f.is_null() { heap::free(c as *mut u8); heap::free(b); return core::ptr::null_mut(); }
        set_cookie(f, c as *mut u8);
        *ptr = b; *sizeloc = 0;
        f
    }
}

// # C: FILE *open_wmemstream(wchar_t **ptr, size_t *sizeloc)
#[no_mangle]
pub unsafe extern "C" fn open_wmemstream(ptr: *mut *mut i32, sizeloc: *mut usize) -> *mut FILE {
    // SAFETY: ptr/sizeloc are writable out-params updated on every wide write,
    // flush, and close. The grown wchar_t buffer is handed to the caller.
    unsafe {
        if ptr.is_null() || sizeloc.is_null() { crate::internal::errno::set(EINVAL); return core::ptr::null_mut(); }
        let cap = 64usize;
        let bytes = cap * core::mem::size_of::<i32>();
        let b = heap::malloc(bytes); if b.is_null() { return core::ptr::null_mut(); }
        *(b as *mut i32) = 0;
        let c = new_cookie(MemCookie {
            buf: b, pos: 0, len: 0, term: 0, cap, readable: false, writable: true,
            nul_term: true, dynamic: true, wide: true, own_buf: true,
            uptr: ptr as *mut *mut u8, usz: sizeloc,
        });
        if c.is_null() { heap::free(b); return core::ptr::null_mut(); }
        let f = alloc_file(-1, 0);
        if f.is_null() { heap::free(c as *mut u8); heap::free(b); return core::ptr::null_mut(); }
        set_cookie(f, c as *mut u8);
        super::file::set_orient(f, 1);
        *ptr = b as *mut i32; *sizeloc = 0;
        f
    }
}

// stream backing choke points — fd-based streams hit the syscall layer,
// memory streams the cookie above. The rest of stdio calls only these.
pub(crate) unsafe fn stream_read(f: *mut FILE, dst: *mut u8, n: usize) -> isize {
    // SAFETY: f is a valid stream; dst is writable for n bytes.
    unsafe {
        if is_mem(f) { mem_read(f, dst, n) }
        else if is_cookie(f) { cookie_read(f, dst, n) }
        else { io::read(fd_of(f), dst, n) }
    }
}
pub(crate) unsafe fn stream_write(f: *mut FILE, src: *const u8, n: usize) -> isize {
    // SAFETY: f is a valid stream; src is readable for n bytes.
    unsafe {
        if is_mem(f) { mem_write(f, src, n) }
        else if is_cookie(f) { cookie_write(f, src, n) }
        else { io::write(fd_of(f), src, n) }
    }
}
pub(crate) unsafe fn stream_seek(f: *mut FILE, off: i64, whence: i32) -> i64 {
    // SAFETY: f is a valid open stream; memory streams reposition the cookie
    // cursor, cookie streams call the seek callback, fd streams lseek.
    unsafe {
        if is_mem(f) { mem_seek(f, off, whence) }
        else if is_cookie(f) { cookie_seek(f, off, whence) }
        else { io::lseek(fd_of(f), off, whence) }
    }
}
pub(crate) unsafe fn stream_tell(f: *mut FILE) -> i64 {
    // SAFETY: f is a valid open stream; report the cookie cursor or the fd's
    // current offset.
    unsafe {
        if is_mem(f) { mem_tell(f) }
        else if is_cookie(f) { cookie_seek(f, 0, io::SEEK_CUR) }
        else { io::lseek(fd_of(f), 0, io::SEEK_CUR) }
    }
}
