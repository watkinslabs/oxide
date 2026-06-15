// <obstack.h> (docs/59) — GNU object-stack memory pools. The public API is
// (almost) all header macros (obstack_alloc/grow/finish/1grow/blank/free/…)
// that expand inline against `struct obstack`; libc.so.6 EXPORTS only the
// underlying helpers those macros call when a chunk boundary is crossed, plus
// the two formatted-output helpers. We implement exactly that exported set:
//   _obstack_begin, _obstack_begin_1, _obstack_newchunk, _obstack_free,
//   _obstack_allocated_p, _obstack_memory_used,
//   obstack_alloc_failed_handler (fn-ptr data symbol),
//   obstack_exit_failure (int data symbol),
//   obstack_printf, obstack_vprintf.
// Ported from glibc malloc/obstack.c; the `struct obstack` layout is byte-for-
// byte the host <obstack.h> so caller-expanded macros interoperate. C ABI only.
#![cfg(feature = "freestanding")]

use core::ffi::{c_void, VaList};

// Lives at the front of each chunk (host `struct _obstack_chunk`).
#[repr(C)]
pub struct ObstackChunk {
    pub limit: *mut u8,             // 1 past end of this chunk
    pub prev: *mut ObstackChunk,    // prior chunk or null
    pub contents: [u8; 4],          // objects begin here
}

// Control block — MUST match host <obstack.h> `struct obstack` field-for-field
// so the inline macros in user code read/write the same offsets. The three
// trailing 1-bit flags pack into one `unsigned` (a u32) low-to-high.
#[repr(C)]
pub struct Obstack {
    pub chunk_size: isize,                  // long: preferred chunk allocation size
    pub chunk: *mut ObstackChunk,           // current chunk
    pub object_base: *mut u8,               // base of object being built
    pub next_free: *mut u8,                 // where next char of current object goes
    pub chunk_limit: *mut u8,               // char after current chunk
    pub temp: ObstackTemp,                  // scratch used by non-GNU macros
    pub alignment_mask: i32,                // mask: object alignment - 1
    pub chunkfun: ChunkFun,                 // chunk allocator
    pub freefun: FreeFun,                   // chunk deallocator
    pub extra_arg: *mut c_void,             // first arg to alloc/dealloc when use_extra_arg
    pub flags: u32,                         // bit0 use_extra_arg, bit1 maybe_empty_object, bit2 alloc_failed
}

#[repr(C)]
pub union ObstackTemp {
    pub tempint: isize, // PTR_INT_TYPE (ptrdiff_t)
    pub tempptr: *mut c_void,
}

// The two prototype shapes the macros cast to (use_extra_arg selects which).
type ChunkFun = Option<unsafe extern "C" fn(*mut c_void, isize) -> *mut ObstackChunk>;
type FreeFun = Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>;
// Plain (no-extra-arg) shapes, as installed by obstack_init/obstack_begin.
type ChunkFunPlain = unsafe extern "C" fn(isize) -> *mut c_void;
type FreeFunPlain = unsafe extern "C" fn(*mut c_void);

const FLAG_USE_EXTRA_ARG: u32 = 1 << 0;
const FLAG_MAYBE_EMPTY_OBJECT: u32 = 1 << 1;

// __BPTR_ALIGN(B,P,A) = B + (((P-B)+A) & ~A). Pointers convert to int, so align
// relative to 0 like the host __PTR_ALIGN fast path.
#[inline]
fn ptr_align(p: *mut u8, align_mask: i32) -> *mut u8 {
    let a = align_mask as usize;
    let pi = p as usize;
    ((pi + a) & !a) as *mut u8
}

mod imp {
    use super::*;
    use core::cell::UnsafeCell;

    // Data symbols. obstack.c declares these as plain globals; a process is
    // free to assign obstack_alloc_failed_handler / obstack_exit_failure.
    #[repr(transparent)]
    struct HandlerCell(UnsafeCell<Option<unsafe extern "C" fn()>>);
    // SAFETY: obstack data symbols are process-wide globals matching glibc's
    // non-thread-local declarations; mutation is the caller's responsibility.
    unsafe impl Sync for HandlerCell {}
    #[repr(transparent)]
    struct I32Cell(UnsafeCell<i32>);
    // SAFETY: obstack_exit_failure is a process-wide global int like glibc's;
    // single-threaded assignment per the obstack contract here too.
    unsafe impl Sync for I32Cell {}

    // # C: void (*obstack_alloc_failed_handler) (void)
    #[no_mangle]
    static obstack_alloc_failed_handler: HandlerCell = HandlerCell(UnsafeCell::new(Some(default_alloc_failed)));
    // # C: int obstack_exit_failure
    #[no_mangle]
    static obstack_exit_failure: I32Cell = I32Cell(UnsafeCell::new(1));

    // Legacy zero-initialized global obstack (BSS) glibc still exports for old
    // a.out-era programs that referenced the implicit single obstack.
    #[repr(transparent)]
    struct ObstackCell(UnsafeCell<Obstack>);
    // SAFETY: legacy process-wide global obstack control block, matching glibc's
    // single static `_obstack`; touched only by code that opts into it.
    unsafe impl Sync for ObstackCell {}
    // # C: struct obstack _obstack
    #[no_mangle]
    static _obstack: ObstackCell = ObstackCell(UnsafeCell::new(Obstack {
        chunk_size: 0, chunk: core::ptr::null_mut(), object_base: core::ptr::null_mut(),
        next_free: core::ptr::null_mut(), chunk_limit: core::ptr::null_mut(),
        temp: ObstackTemp { tempint: 0 }, alignment_mask: 0, chunkfun: None, freefun: None,
        extra_arg: core::ptr::null_mut(), flags: 0,
    }));

    extern "C" {
        fn abort() -> !;
        fn write(fd: i32, buf: *const u8, n: usize) -> isize;
    }

    // Default handler: print a message and abort (glibc print_and_abort).
    unsafe extern "C" fn default_alloc_failed() {
        const MSG: &[u8] = b"memory exhausted\n";
        // SAFETY: write the diagnostic to stderr (fd 2) then abort; MSG is a
        // 'static byte string of known length, no aliasing or freeing involved.
        unsafe {
            write(2, MSG.as_ptr(), MSG.len());
            abort();
        }
    }

    // Invoke the installed (or default) failure handler; it must not return.
    unsafe fn call_alloc_failed() -> ! {
        // SAFETY: reads the process-global handler pointer (never null: seeded
        // with default_alloc_failed) and calls it; contract says it never returns.
        unsafe {
            if let Some(h) = *obstack_alloc_failed_handler.0.get() { h(); }
            // Handler is contractually non-returning; abort if it misbehaves.
            default_alloc_failed();
            abort()
        }
    }

    // Allocate a chunk via the obstack's installed allocator (extra-arg aware).
    unsafe fn call_chunk_alloc(h: *mut Obstack, size: isize) -> *mut ObstackChunk {
        // SAFETY: h is a live obstack; dispatch to chunkfun honoring the
        // use_extra_arg flag exactly as the header macros set it up.
        unsafe {
            let hr = &*h;
            if hr.flags & FLAG_USE_EXTRA_ARG != 0 {
                match hr.chunkfun { Some(f) => f(hr.extra_arg, size), None => core::ptr::null_mut() }
            } else {
                // Plain shape fn(long)->void*; the struct stores it cast to the
                // extra-arg type, so transmute back to the no-arg prototype.
                let p: ChunkFunPlain = core::mem::transmute(hr.chunkfun);
                p(size) as *mut ObstackChunk
            }
        }
    }

    // Free a chunk via the installed deallocator (extra-arg aware).
    unsafe fn call_chunk_free(h: *mut Obstack, chunk: *mut ObstackChunk) {
        // SAFETY: h live; chunk previously returned by call_chunk_alloc; dispatch
        // to freefun honoring use_extra_arg as the header macros configured it.
        unsafe {
            let hr = &*h;
            if hr.flags & FLAG_USE_EXTRA_ARG != 0 {
                if let Some(f) = hr.freefun { f(hr.extra_arg, chunk as *mut c_void); }
            } else {
                let p: FreeFunPlain = core::mem::transmute(hr.freefun);
                p(chunk as *mut c_void);
            }
        }
    }

    // Core of _obstack_begin / _obstack_begin_1 (glibc _obstack_begin_worker).
    unsafe fn begin_worker(h: *mut Obstack, mut size: isize, mut alignment: isize) -> i32 {
        // SAFETY: h points to caller-provided (uninitialized) struct obstack; we
        // initialize every field, mirroring glibc _obstack_begin_worker exactly.
        unsafe {
            if alignment == 0 { alignment = core::mem::align_of::<isize>() as isize; }
            if size == 0 {
                // glibc: a size near 4096 minus chunk overhead/extra slop.
                let extra = (12 + core::mem::size_of::<ObstackChunk>() as isize - 1)
                    & !((core::mem::align_of::<isize>() as isize) - 1);
                size = 4096 - extra;
            }

            let hr = &mut *h;
            hr.chunk_size = size;
            hr.alignment_mask = (alignment - 1) as i32;
            // Clear maybe_empty_object; preserve use_extra_arg (set before begin).
            hr.flags &= FLAG_USE_EXTRA_ARG;

            let chunk = call_chunk_alloc(h, size);
            if chunk.is_null() { call_alloc_failed(); }
            let hr = &mut *h;
            hr.chunk = chunk;
            let base = (*chunk).contents.as_mut_ptr();
            hr.object_base = ptr_align(base, hr.alignment_mask);
            hr.next_free = hr.object_base;
            let limit = (chunk as *mut u8).add(size as usize);
            hr.chunk_limit = limit;
            (*chunk).limit = limit;
            (*chunk).prev = core::ptr::null_mut();
            1
        }
    }

    // # C: int _obstack_begin (struct obstack *h, int size, int alignment, void *(*chunkfun)(long), void (*freefun)(void *))
    #[no_mangle]
    pub unsafe extern "C" fn _obstack_begin(
        h: *mut Obstack, size: i32, alignment: i32,
        chunkfun: Option<ChunkFunPlain>, freefun: Option<FreeFunPlain>,
    ) -> i32 {
        // SAFETY: h is caller storage; install the plain (no-extra-arg) allocator
        // pair by transmuting to the stored extra-arg prototype, then init.
        unsafe {
            let hr = &mut *h;
            hr.chunkfun = core::mem::transmute::<Option<ChunkFunPlain>, ChunkFun>(chunkfun);
            hr.freefun = core::mem::transmute::<Option<FreeFunPlain>, FreeFun>(freefun);
            hr.extra_arg = core::ptr::null_mut();
            hr.flags = 0; // use_extra_arg = 0
            begin_worker(h, size as isize, alignment as isize)
        }
    }

    // # C: int _obstack_begin_1 (struct obstack *h, int size, int alignment, void *(*chunkfun)(void *, long), void (*freefun)(void *, void *), void *arg)
    #[no_mangle]
    pub unsafe extern "C" fn _obstack_begin_1(
        h: *mut Obstack, size: i32, alignment: i32,
        chunkfun: ChunkFun, freefun: FreeFun, arg: *mut c_void,
    ) -> i32 {
        // SAFETY: h is caller storage; install the extra-arg allocator pair, record
        // arg, set use_extra_arg, then run the common initializer.
        unsafe {
            let hr = &mut *h;
            hr.chunkfun = chunkfun;
            hr.freefun = freefun;
            hr.extra_arg = arg;
            hr.flags = FLAG_USE_EXTRA_ARG;
            begin_worker(h, size as isize, alignment as isize)
        }
    }

    // # C: void _obstack_newchunk (struct obstack *h, int length)
    #[no_mangle]
    pub unsafe extern "C" fn _obstack_newchunk(h: *mut Obstack, length: i32) {
        // SAFETY: h is a live obstack with a partially built current object; we
        // allocate a bigger chunk, relocate the object, and relink — glibc parity.
        unsafe {
            let hr = &mut *h;
            let obj_size = hr.next_free as isize - hr.object_base as isize;

            // New chunk big enough for current object + requested length + slop.
            let mut new_size = obj_size + length as isize + 100 + hr.chunk_size;
            if new_size < hr.chunk_size { new_size = hr.chunk_size; }

            let new_chunk = call_chunk_alloc(h, new_size);
            if new_chunk.is_null() { call_alloc_failed(); }
            let hr = &mut *h;
            (*new_chunk).prev = hr.chunk;
            let new_limit = (new_chunk as *mut u8).add(new_size as usize);
            (*new_chunk).limit = new_limit;

            // Aligned destination for the relocated object in the new chunk.
            let dst_base = ptr_align((*new_chunk).contents.as_mut_ptr(), hr.alignment_mask);
            super::copy_bytes(dst_base, hr.object_base, obj_size as usize);

            // The old chunk can be freed only if it held no other (finished)
            // object: object_base sits at the chunk's aligned contents start and
            // there is no maybe-empty zero-length object pinning it.
            let old_chunk = hr.chunk;
            let contents_start = ptr_align((*old_chunk).contents.as_mut_ptr(), hr.alignment_mask);
            let frees_old = hr.object_base == contents_start && (hr.flags & FLAG_MAYBE_EMPTY_OBJECT) == 0;
            let prev_of_old = (*old_chunk).prev;

            hr.chunk_limit = new_limit;
            hr.object_base = dst_base;
            hr.next_free = dst_base.add(obj_size as usize);
            hr.chunk = new_chunk;
            if frees_old {
                (*new_chunk).prev = prev_of_old;
                call_chunk_free(h, old_chunk);
            }
            let hr = &mut *h;
            hr.flags &= !FLAG_MAYBE_EMPTY_OBJECT;
        }
    }

    // # C: void obstack_free (struct obstack *h, void *obj)
    // Alias of _obstack_free (host libc exports both at the same address; the
    // header's __obstack_free macro defaults to the unprefixed name).
    #[no_mangle]
    pub unsafe extern "C" fn obstack_free(h: *mut Obstack, obj: *mut c_void) {
        // SAFETY: thin alias forwarding to the prefixed implementation.
        unsafe { _obstack_free(h, obj) }
    }

    // # C: void _obstack_free (struct obstack *h, void *obj)
    #[no_mangle]
    pub unsafe extern "C" fn _obstack_free(h: *mut Obstack, obj: *mut c_void) {
        // SAFETY: h is a live obstack; free every chunk whose range excludes obj,
        // then reset the current-object pointers to obj (glibc obstack_free).
        unsafe {
            let hr = &mut *h;
            let mut lp = hr.chunk;
            let target = obj as *mut u8;
            while !lp.is_null() && (target < lp as *mut u8 || target > (*lp).limit) {
                let plp = (*lp).prev;
                call_chunk_free(h, lp);
                lp = plp;
                let hr = &mut *h;
                hr.flags &= !FLAG_MAYBE_EMPTY_OBJECT;
            }
            let hr = &mut *h;
            if !lp.is_null() {
                hr.object_base = target;
                hr.next_free = target;
                hr.chunk_limit = (*lp).limit;
                hr.chunk = lp;
            } else if !obj.is_null() {
                // obj not in any chunk and not null => caller error; leave empty.
                hr.chunk = core::ptr::null_mut();
            }
        }
    }

    // # C: int _obstack_allocated_p (struct obstack *h, void *obj)
    #[no_mangle]
    pub unsafe extern "C" fn _obstack_allocated_p(h: *mut Obstack, obj: *mut c_void) -> i32 {
        // SAFETY: h is a live obstack; scan the chunk list for one containing obj.
        unsafe {
            let hr = &*h;
            let mut lp = hr.chunk;
            let target = obj as *mut u8;
            while !lp.is_null() && (target < lp as *mut u8 || target > (*lp).limit) {
                lp = (*lp).prev;
            }
            i32::from(!lp.is_null())
        }
    }

    // # C: _OBSTACK_SIZE_T _obstack_memory_used (struct obstack *h)
    #[no_mangle]
    pub unsafe extern "C" fn _obstack_memory_used(h: *mut Obstack) -> usize {
        // SAFETY: h is a live obstack; sum (limit - chunk) over every chunk.
        unsafe {
            let hr = &*h;
            let mut nbytes: usize = 0;
            let mut lp = hr.chunk;
            while !lp.is_null() {
                nbytes += (*lp).limit as usize - lp as usize;
                lp = (*lp).prev;
            }
            nbytes
        }
    }

    extern "C" {
        fn vsnprintf(s: *mut u8, n: usize, fmt: *const u8, ap: VaList) -> i32;
    }

    // Format into the obstack's growing object (glibc obstack_vprintf): measure
    // with a 0-length vsnprintf, make room, format for real, advance next_free by
    // the byte count (leaving the trailing NUL written but not part of the object).
    unsafe fn vprintf_worker(obstack: *mut Obstack, format: *const u8, ap: &mut VaList) -> i32 {
        // SAFETY: obstack is live; we grow it by the formatted length and write the
        // bytes contiguously into the current object, matching glibc behavior.
        unsafe {
            let needed = vsnprintf(core::ptr::null_mut(), 0, format, ap.clone());
            if needed < 0 { return needed; }
            let n = needed as usize;
            super::obstack_make_room(obstack, (n + 1) as isize);
            let hr = &mut *obstack;
            let dst = hr.next_free;
            vsnprintf(dst, n + 1, format, ap.clone());
            let hr = &mut *obstack;
            hr.next_free = hr.next_free.add(n);
            needed
        }
    }

    // # C: int obstack_vprintf (struct obstack *obstack, const char *format, va_list args)
    #[no_mangle]
    pub unsafe extern "C" fn obstack_vprintf(obstack: *mut Obstack, format: *const u8, mut args: VaList) -> i32 {
        // SAFETY: args holds the matching varargs; the worker grows the obstack by
        // the formatted byte count and writes them into the current object.
        unsafe { vprintf_worker(obstack, format, &mut args) }
    }

    // # C: int obstack_printf (struct obstack *obstack, const char *format, ...)
    #[no_mangle]
    pub unsafe extern "C" fn obstack_printf(obstack: *mut Obstack, format: *const u8, mut args: ...) -> i32 {
        // SAFETY: args supplies the varargs named by format; delegate to the
        // va_list worker which grows the obstack by the formatted byte count.
        unsafe { vprintf_worker(obstack, format, &mut args) }
    }

    // _FORTIFY_SOURCE redirections (GLIBC_2.8). The leading `flag` selects the
    // checked behavior; we have nothing extra to verify on the obstack, so just
    // forward to the unchecked worker.
    // # C: int __obstack_vprintf_chk (struct obstack *obstack, int flag, const char *format, va_list args)
    #[no_mangle]
    pub unsafe extern "C" fn __obstack_vprintf_chk(obstack: *mut Obstack, _flag: i32, format: *const u8, mut args: VaList) -> i32 {
        // SAFETY: fortify alias; args holds the varargs, delegate to the worker.
        unsafe { vprintf_worker(obstack, format, &mut args) }
    }
    // # C: int __obstack_printf_chk (struct obstack *obstack, int flag, const char *format, ...)
    #[no_mangle]
    pub unsafe extern "C" fn __obstack_printf_chk(obstack: *mut Obstack, _flag: i32, format: *const u8, mut args: ...) -> i32 {
        // SAFETY: fortify alias; args supplies the varargs named by format.
        unsafe { vprintf_worker(obstack, format, &mut args) }
    }
}

// Bytewise copy used by _obstack_newchunk. Crate-internal, no C ABI.
#[inline]
unsafe fn copy_bytes(dst: *mut u8, src: *const u8, n: usize) {
    // SAFETY: dst is freshly allocated chunk space of >= n bytes; src is the
    // current object of exactly n bytes; the regions do not overlap (new chunk).
    unsafe { core::ptr::copy_nonoverlapping(src, dst, n); }
}

// obstack_make_room equivalent (header macro): if the current chunk lacks room
// for `length` more bytes, allocate a new (relocating) chunk.
#[inline]
unsafe fn obstack_make_room(h: *mut Obstack, length: isize) {
    // SAFETY: h is a live obstack; compares remaining chunk room against length
    // and triggers a relocating new-chunk allocation when short, like the macro.
    unsafe {
        let hr = &*h;
        if (hr.chunk_limit as isize - hr.next_free as isize) < length {
            imp::_obstack_newchunk(h, length as i32);
        }
    }
}
