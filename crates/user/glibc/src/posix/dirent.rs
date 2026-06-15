// Directory reading (docs/59§6 G8). The kernel linux_dirent64 has the
// same field order as glibc struct dirent (d_ino, d_off, d_reclen,
// d_type, d_name), so readdir returns a pointer straight into the DIR
// buffer that getdents64 filled — no per-entry copy. DIR is opaque to C.
// Layout golden: d_type@18, d_name@19.

#[repr(C)]
pub struct dirent {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [u8; 256],
}

// d_name must sit at offset 19 to match the kernel's variable-length entries.
const _: () = {
    assert!(core::mem::offset_of!(dirent, d_off) == 8);
    assert!(core::mem::offset_of!(dirent, d_reclen) == 16);
    assert!(core::mem::offset_of!(dirent, d_type) == 18);
    assert!(core::mem::offset_of!(dirent, d_name) == 19);
};

#[cfg(feature = "freestanding")]
pub(crate) use imp::{closedir, opendir, readdir};

#[cfg(feature = "freestanding")]
mod imp {
    use super::dirent;
    use crate::arch::syscall::sys3;
    use crate::internal::errno::ret_isize;
    use crate::internal::nr;
    use crate::posix::io::{self, AT_FDCWD};

    const BUF: usize = 32768;

    #[repr(C)]
    #[allow(clippy::upper_case_acronyms)] // DIR is the standard C type name
    pub struct DIR { fd: i32, pos: usize, end: usize, last_off: i64, buf: [u8; BUF] }

    unsafe fn alloc_dir(fd: i32) -> *mut DIR {
        // SAFETY: heap-allocate a DIR and initialise its scalar fields; the
        // buffer is filled on demand by readdir.
        unsafe {
            let d = crate::malloc::heap::malloc(core::mem::size_of::<DIR>()) as *mut DIR;
            if !d.is_null() { (*d).fd = fd; (*d).pos = 0; (*d).end = 0; (*d).last_off = 0; }
            d
        }
    }

    // # C: DIR *opendir(const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn opendir(name: *const u8) -> *mut DIR {
        // SAFETY: name NUL-terminated; open the dir then wrap its fd.
        unsafe {
            let fd = io::openat(AT_FDCWD, name, io::O_RDONLY | io::O_DIRECTORY | io::O_CLOEXEC, 0);
            if fd < 0 { return core::ptr::null_mut(); }
            let d = alloc_dir(fd);
            if d.is_null() { io::close(fd); }
            d
        }
    }
    // # C: DIR *fdopendir(int fd)
    #[no_mangle]
    pub unsafe extern "C" fn fdopendir(fd: i32) -> *mut DIR {
        // SAFETY: fd is an open directory descriptor the caller hands over.
        unsafe { alloc_dir(fd) }
    }
    // # C: struct dirent *readdir(DIR *d)
    #[no_mangle]
    pub unsafe extern "C" fn readdir(d: *mut DIR) -> *mut dirent {
        // SAFETY: d is a valid DIR; refill via getdents64 when drained, then
        // return a pointer to the current entry inside the buffer.
        unsafe {
            if (*d).pos >= (*d).end {
                let r = ret_isize(sys3(nr::GETDENTS64, (*d).fd as usize, (*d).buf.as_mut_ptr() as usize, BUF));
                if r <= 0 { return core::ptr::null_mut(); }
                (*d).end = r as usize;
                (*d).pos = 0;
            }
            let e = (*d).buf.as_mut_ptr().add((*d).pos) as *mut dirent;
            (*d).pos += (*e).d_reclen as usize;
            (*d).last_off = (*e).d_off; // seek offset of the NEXT entry → telldir
            e
        }
    }
    // # C: struct dirent *readdir64(DIR *d) — same as readdir (LFS).
    #[no_mangle]
    pub unsafe extern "C" fn readdir64(d: *mut DIR) -> *mut dirent {
        // SAFETY: alias of readdir; identical 64-bit layout.
        unsafe { readdir(d) }
    }
    // # C: int alphasort(const struct dirent **a, const struct dirent **b)
    #[no_mangle]
    pub unsafe extern "C" fn alphasort(a: *const *const dirent, b: *const *const dirent) -> i32 {
        // SAFETY: a/b point to dirent pointers (scandir comparator); compare the
        // NUL-terminated d_name fields by C-locale collation (== strcmp).
        unsafe { crate::string::cmp::strcmp_impl((*(*a)).d_name.as_ptr(), (*(*b)).d_name.as_ptr()) }
    }
    // # C: int versionsort(const struct dirent **a, const struct dirent **b)
    #[no_mangle]
    pub unsafe extern "C" fn versionsort(a: *const *const dirent, b: *const *const dirent) -> i32 {
        // SAFETY: a/b point to dirent pointers; natural-version compare on d_name.
        unsafe { crate::string::cmp::strverscmp_impl((*(*a)).d_name.as_ptr(), (*(*b)).d_name.as_ptr()) }
    }
    // # C: int alphasort64(...) — LFS alias
    // SAFETY: identical dirent layout on LP64; forwards to alphasort.
    #[no_mangle] pub unsafe extern "C" fn alphasort64(a: *const *const dirent, b: *const *const dirent) -> i32 { unsafe { alphasort(a, b) } }
    // # C: int versionsort64(...) — LFS alias
    // SAFETY: identical dirent layout on LP64; forwards to versionsort.
    #[no_mangle] pub unsafe extern "C" fn versionsort64(a: *const *const dirent, b: *const *const dirent) -> i32 { unsafe { versionsort(a, b) } }
    type FilterFn = extern "C" fn(*const dirent) -> i32;
    type CmpFn = extern "C" fn(*const *const dirent, *const *const dirent) -> i32;

    // # C: int scandir(const char *dir, struct dirent ***namelist, filter, compar)
    #[no_mangle]
    pub unsafe extern "C" fn scandir(dirp: *const u8, namelist: *mut *mut *mut dirent, filter: Option<FilterFn>, compar: Option<CmpFn>) -> i32 {
        // SAFETY: dirp NUL-terminated; namelist a writable out-param. Reads all
        // entries, applies filter, malloc-copies survivors into a grown array,
        // sorts with compar (each element a dirent* — qsort passes &elem, the
        // dirent** compar expects), and publishes the array. -1 on open error.
        unsafe {
            let d = opendir(dirp);
            if d.is_null() { return -1; }
            let mut arr: *mut *mut dirent = core::ptr::null_mut();
            let (mut cap, mut cnt) = (0usize, 0usize);
            loop {
                let e = readdir(d);
                if e.is_null() { break; }
                if let Some(f) = filter { if f(e) == 0 { continue; } }
                let sz = (*e).d_reclen as usize;
                let copy = crate::malloc::heap::malloc(sz) as *mut dirent;
                if copy.is_null() { continue; }
                core::ptr::copy_nonoverlapping(e as *const u8, copy as *mut u8, sz);
                if cnt == cap {
                    cap = if cap == 0 { 16 } else { cap * 2 };
                    arr = crate::malloc::heap::realloc(arr as *mut u8, cap * 8) as *mut *mut dirent;
                }
                *arr.add(cnt) = copy;
                cnt += 1;
            }
            closedir(d);
            if let Some(c) = compar {
                // qsort over the dirent* array; the element addr (&dirent*) is
                // exactly the `const dirent **` the comparator expects.
                let cmp: crate::stdlib::sort::Cmp = core::mem::transmute(c);
                crate::stdlib::sort::qsort_impl(arr as *mut u8, cnt, 8, cmp);
            }
            *namelist = arr;
            cnt as i32
        }
    }
    // # C: int scandir64(...) — LFS alias
    #[no_mangle]
    pub unsafe extern "C" fn scandir64(dirp: *const u8, namelist: *mut *mut *mut dirent, filter: Option<FilterFn>, compar: Option<CmpFn>) -> i32 {
        // SAFETY: identical dirent layout on LP64; forwards to scandir.
        unsafe { scandir(dirp, namelist, filter, compar) }
    }

    // # C: int closedir(DIR *d)
    #[no_mangle]
    pub unsafe extern "C" fn closedir(d: *mut DIR) -> i32 {
        // SAFETY: d came from opendir/fdopendir; close fd + free the DIR.
        unsafe {
            if d.is_null() { return -1; }
            let r = io::close((*d).fd);
            crate::malloc::heap::free(d as *mut u8);
            r
        }
    }
    // # C: void rewinddir(DIR *d)
    #[no_mangle]
    pub unsafe extern "C" fn rewinddir(d: *mut DIR) {
        // SAFETY: d is valid; seek to 0 and drop the buffered entries.
        unsafe {
            io::lseek((*d).fd, 0, io::SEEK_SET);
            (*d).pos = 0;
            (*d).end = 0;
            (*d).last_off = 0;
        }
    }
    // # C: int dirfd(DIR *d)
    #[no_mangle]
    pub unsafe extern "C" fn dirfd(d: *mut DIR) -> i32 {
        // SAFETY: d is a valid DIR; read its descriptor.
        unsafe { (*d).fd }
    }

    // # C: int readdir_r(DIR *d, struct dirent *entry, struct dirent **result)
    #[no_mangle]
    pub unsafe extern "C" fn readdir_r(d: *mut DIR, entry: *mut dirent, result: *mut *mut dirent) -> i32 {
        // SAFETY: d is a valid DIR; entry is caller-provided dirent storage and
        // result a writable out-param. Copy the next entry into *entry, publish
        // it via *result (NULL at end-of-dir), return 0 (errno-style).
        unsafe {
            let e = readdir(d);
            if e.is_null() { *result = core::ptr::null_mut(); return 0; }
            let sz = (*e).d_reclen as usize;
            core::ptr::copy_nonoverlapping(e as *const u8, entry as *mut u8, sz);
            *result = entry;
            0
        }
    }
    // # C: int readdir64_r(DIR *d, struct dirent64 *entry, struct dirent64 **result)
    #[no_mangle]
    pub unsafe extern "C" fn readdir64_r(d: *mut DIR, entry: *mut dirent, result: *mut *mut dirent) -> i32 {
        // SAFETY: identical dirent layout on LP64; forwards to readdir_r.
        unsafe { readdir_r(d, entry, result) }
    }

    // # C: long telldir(DIR *d)
    #[no_mangle]
    pub unsafe extern "C" fn telldir(d: *mut DIR) -> i64 {
        // SAFETY: d is a valid DIR; return the kernel d_off recorded for the next
        // entry to read (0 at start). seekdir round-trips this opaque value.
        unsafe { (*d).last_off }
    }
    // # C: void seekdir(DIR *d, long loc)
    #[no_mangle]
    pub unsafe extern "C" fn seekdir(d: *mut DIR, loc: i64) {
        // SAFETY: d is a valid DIR; loc was returned by telldir on this stream.
        // lseek the directory fd to that offset and drop the buffer so the next
        // readdir refills from there.
        unsafe {
            io::lseek((*d).fd, loc, io::SEEK_SET);
            (*d).pos = 0;
            (*d).end = 0;
            (*d).last_off = loc;
        }
    }
}
