// execinfo.h — backtrace via a frame-pointer chain walk (docs/59§6 G8).
// Each frame links to its caller through the saved frame pointer (rbp on
// x86_64, x29 on aarch64): [saved_fp][return_addr] at the frame base, so
// walking the fp chain yields the return-address array. backtrace_symbols
// formats each address as a hex "[0xADDR]" string (one heap block, glibc's
// single-allocation convention); _fd writes the same lines to a descriptor.
// Frame-pointer omission would break the walk, so libc is built with frame
// pointers for these paths. Freestanding only.
#![cfg(feature = "freestanding")]

// Walk the frame-pointer chain, storing up to `size` return addresses.
// # C: int backtrace(void **buffer, int size)
#[no_mangle]
pub unsafe extern "C" fn backtrace(buffer: *mut *mut core::ffi::c_void, size: i32) -> i32 {
    // SAFETY: buffer is a caller array of `size` void* slots. We read the
    // current frame pointer, then follow [fp]=caller_fp / [fp+8]=ret_addr,
    // stopping at a null/unaligned fp or when the array fills. Only well-formed
    // ABI frames are dereferenced; a corrupt chain terminates the walk.
    unsafe {
        if buffer.is_null() || size <= 0 { return 0; }
        let mut fp = frame_pointer();
        let mut n = 0i32;
        while n < size && fp != 0 && fp & (core::mem::size_of::<usize>() - 1) == 0 {
            let slots = fp as *const usize;
            let ret = *slots.add(1); // saved return address
            if ret == 0 { break; }
            *buffer.add(n as usize) = ret as *mut core::ffi::c_void;
            n += 1;
            let next = *slots; // saved caller frame pointer
            if next <= fp { break; } // stacks grow down; fp must increase
            fp = next;
        }
        n
    }
}

#[inline(always)]
fn frame_pointer() -> usize {
    let fp: usize;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: reads the current frame-base register (rbp); pure register move,
    // no memory access, valid in a frame-pointer-preserving build.
    unsafe { core::arch::asm!("mov {}, rbp", out(reg) fp, options(nomem, nostack, preserves_flags)); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: reads the AArch64 frame register x29; pure register move with no
    // memory access, valid in a frame-pointer-preserving build.
    unsafe { core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack, preserves_flags)); }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { fp = 0; }
    fp
}

// # C: char **backtrace_symbols(void *const *buffer, int size)
#[no_mangle]
pub unsafe extern "C" fn backtrace_symbols(buffer: *const *mut core::ffi::c_void, size: i32) -> *mut *mut u8 {
    // SAFETY: buffer holds `size` addresses. One heap block holds the char*
    // pointer array followed by the formatted strings, so the caller frees it
    // with a single free() (glibc's contract). NULL on size<=0 or OOM.
    unsafe {
        if buffer.is_null() || size <= 0 { return core::ptr::null_mut(); }
        let n = size as usize;
        // Each line "[0xHHHHHHHHHHHHHHHH]\0" ≤ 21 bytes; reserve generously.
        const LINE_MAX: usize = 32;
        let total = n * core::mem::size_of::<*mut u8>() + n * LINE_MAX;
        let base = crate::malloc::heap::malloc(total);
        if base.is_null() { return core::ptr::null_mut(); }
        let arr = base as *mut *mut u8;
        let mut off = n * core::mem::size_of::<*mut u8>();
        for i in 0..n {
            let addr = *buffer.add(i) as usize;
            let dst = base.add(off);
            let len = fmt_addr(addr, dst);
            *arr.add(i) = dst;
            off += len + 1;
        }
        arr
    }
}

// # C: void backtrace_symbols_fd(void *const *buffer, int size, int fd)
#[no_mangle]
pub unsafe extern "C" fn backtrace_symbols_fd(buffer: *const *mut core::ffi::c_void, size: i32, fd: i32) {
    // SAFETY: buffer holds `size` addresses; we format each into a small stack
    // buffer and write it (plus a newline) to fd via write(2), no allocation.
    unsafe {
        if buffer.is_null() { return; }
        for i in 0..size.max(0) as usize {
            let addr = *buffer.add(i) as usize;
            let mut line = [0u8; 33];
            let len = fmt_addr(addr, line.as_mut_ptr());
            line[len] = b'\n';
            crate::posix::io::write(fd, line.as_ptr(), len + 1);
        }
    }
}

// Format "[0xADDR]" + NUL into dst; returns the length excluding the NUL.
unsafe fn fmt_addr(addr: usize, dst: *mut u8) -> usize {
    // SAFETY: dst has room for the fixed "[0x..]\0" form (≤ 21 bytes). We write
    // the bracketed lowercase-hex address (no leading zeros, "0" if zero)
    // followed by a NUL.
    unsafe {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut tmp = [0u8; 16]; // up to 16 hex nibbles for a 64-bit address
        let mut hl = 0;
        let mut v = addr;
        if v == 0 { tmp[0] = b'0'; hl = 1; }
        while v != 0 { tmp[hl] = HEX[v & 0xf]; v >>= 4; hl += 1; }
        let mut i = 0;
        *dst.add(i) = b'['; i += 1;
        *dst.add(i) = b'0'; i += 1;
        *dst.add(i) = b'x'; i += 1;
        for k in (0..hl).rev() { *dst.add(i) = tmp[k]; i += 1; } // reverse to MSB-first
        *dst.add(i) = b']'; i += 1;
        *dst.add(i) = 0;
        i
    }
}
