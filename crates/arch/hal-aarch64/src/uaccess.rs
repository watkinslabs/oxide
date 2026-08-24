#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const CMPXCHG_RETRY_LIMIT: u32 = 128;

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
core::arch::global_asm!(r#"
    .global oxide_raw_copy_from_user
    .type oxide_raw_copy_from_user, %function
oxide_raw_copy_from_user:
    cbz x2, 3f
    cmp x2, #8
    b.lo 31f
30: ldr x3, [x1], #8
32: str x3, [x0], #8
    subs x2, x2, #8
    cmp x2, #8
    b.hs 30b
31: cbz x2, 3f
33: ldrb w3, [x1], #1
34: strb w3, [x0], #1
    subs x2, x2, #1
    b.ne 33b
3:  mov x0, #0
    ret
4:  mov x0, x2
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 30b - .
    .long 4b - .
    .long 32b - .
    .long 4b - .
    .long 33b - .
    .long 4b - .
    .long 34b - .
    .long 4b - .
    .popsection
    .size oxide_raw_copy_from_user, . - oxide_raw_copy_from_user

    .global oxide_raw_copy_to_user
    .type oxide_raw_copy_to_user, %function
oxide_raw_copy_to_user:
    cbz x2, 7f
    cmp x2, #8
    b.lo 41f
40: ldr x3, [x1], #8
42: str x3, [x0], #8
    subs x2, x2, #8
    cmp x2, #8
    b.hs 40b
41: cbz x2, 7f
43: ldrb w3, [x1], #1
44: strb w3, [x0], #1
    subs x2, x2, #1
    b.ne 43b
7:  mov x0, #0
    ret
8:  mov x0, x2
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 40b - .
    .long 8b - .
    .long 42b - .
    .long 8b - .
    .long 43b - .
    .long 8b - .
    .long 44b - .
    .long 8b - .
    .popsection
    .size oxide_raw_copy_to_user, . - oxide_raw_copy_to_user

    .global oxide_raw_cmpxchg_user_u32
    .type oxide_raw_cmpxchg_user_u32, %function
oxide_raw_cmpxchg_user_u32:
    mov w6, #{retry_limit}
    mov w4, wzr
9:  ldaxr w5, [x0]
    cmp w5, w1
    b.ne 12f
10: stlxr w4, w2, [x0]
    cbz w4, 11f
    subs w6, w6, #1
    b.ne 9b
    dmb ish
    mov w0, #2
    ret
11: dmb ish
12: str w5, [x3]
    mov w0, wzr
    ret
13: mov w0, #1
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 9b - .
    .long 13b - .
    .long 10b - .
    .long 13b - .
    .popsection
    .size oxide_raw_cmpxchg_user_u32, . - oxide_raw_cmpxchg_user_u32

    .global oxide_raw_get_user_u32
    .type oxide_raw_get_user_u32, %function
oxide_raw_get_user_u32:
14: ldr w2, [x0]
    str w2, [x1]
    mov w0, wzr
    ret
15: mov w0, #1
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 14b - .
    .long 15b - .
    .popsection
    .size oxide_raw_get_user_u32, . - oxide_raw_get_user_u32

    .global oxide_raw_get_user_u64
    .type oxide_raw_get_user_u64, %function
oxide_raw_get_user_u64:
16: ldr x2, [x0]
    str x2, [x1]
    mov w0, wzr
    ret
17: mov w0, #1
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 16b - .
    .long 17b - .
    .popsection
    .size oxide_raw_get_user_u64, . - oxide_raw_get_user_u64

    .global oxide_raw_put_user_u32
    .type oxide_raw_put_user_u32, %function
oxide_raw_put_user_u32:
18: str w1, [x0]
    mov w0, wzr
    ret
19: mov w0, #1
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 18b - .
    .long 19b - .
    .popsection
    .size oxide_raw_put_user_u32, . - oxide_raw_put_user_u32

    .global oxide_raw_put_user_u64
    .type oxide_raw_put_user_u64, %function
oxide_raw_put_user_u64:
20: str x1, [x0]
    mov w0, wzr
    ret
21: mov w0, #1
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 20b - .
    .long 21b - .
    .popsection
    .size oxide_raw_put_user_u64, . - oxide_raw_put_user_u64
"#, retry_limit = const CMPXCHG_RETRY_LIMIT);

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_raw_copy_from_user(dst: *mut u8, src: *const u8, len: usize) -> usize;
    fn oxide_raw_copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> usize;
    fn oxide_raw_cmpxchg_user_u32(uaddr: *mut u32, old: u32, new: u32, seen: *mut u32) -> u32;
    fn oxide_raw_get_user_u32(src: *const u32, out: *mut u32) -> u32;
    fn oxide_raw_get_user_u64(src: *const u64, out: *mut u64) -> u32;
    fn oxide_raw_put_user_u32(dst: *mut u32, value: u32) -> u32;
    fn oxide_raw_put_user_u64(dst: *mut u64, value: u64) -> u32;
}

/// Copy from user and return bytes not copied. # C: O(len + page faults)
pub unsafe fn raw_copy_from_user(dst: *mut u8, src: *const u8, len: usize) -> usize {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: caller supplies nonoverlapping spans; asm returns uncopied bytes after extable recovery.
        unsafe { oxide_raw_copy_from_user(dst, src, len) }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    {
        // SAFETY: hosted caller supplies valid nonoverlapping spans.
        unsafe { core::ptr::copy_nonoverlapping(src, dst, len); }
        0
    }
}

/// Copy to user and return bytes not copied. # C: O(len + page faults)
pub unsafe fn raw_copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> usize {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: caller supplies nonoverlapping spans; asm returns uncopied bytes after extable recovery.
        unsafe { oxide_raw_copy_to_user(dst, src, len) }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    {
        // SAFETY: hosted caller supplies valid nonoverlapping spans.
        unsafe { core::ptr::copy_nonoverlapping(src, dst, len); }
        0
    }
}

/// Atomically replace a user word; 0 succeeds, 1 faults, 2 requests retry. # C: O(page faults)
pub unsafe fn raw_cmpxchg_user_u32(uaddr: *mut u32, old: u32, new: u32, seen: *mut u32) -> u32 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: caller supplies a user word and live output; asm recovers both faultable exclusive accesses.
        unsafe { oxide_raw_cmpxchg_user_u32(uaddr, old, new, seen) }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    {
        use core::sync::atomic::{AtomicU32, Ordering};
        // SAFETY: hosted caller supplies a naturally aligned live AtomicU32-compatible word.
        let cell = unsafe { &*(uaddr as *const AtomicU32) };
        let value = match cell.compare_exchange(old, new, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(v) | Err(v) => v,
        };
        // SAFETY: caller supplies a live output word that does not alias the user word.
        unsafe { seen.write(value); }
        0
    }
}

/// Read one user u32; zero succeeds and one reports a fault. # C: O(1)
pub unsafe fn raw_get_user_u32(src: *const u32, out: *mut u32) -> u32 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { unsafe { oxide_raw_get_user_u32(src, out) } }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { unsafe { out.write(src.read()); } 0 }
}

/// Read one user u64; zero succeeds and one reports a fault. # C: O(1)
pub unsafe fn raw_get_user_u64(src: *const u64, out: *mut u64) -> u32 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { unsafe { oxide_raw_get_user_u64(src, out) } }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { unsafe { out.write(src.read()); } 0 }
}

/// Write one user u32; zero succeeds and one reports a fault. # C: O(1)
pub unsafe fn raw_put_user_u32(dst: *mut u32, value: u32) -> u32 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { unsafe { oxide_raw_put_user_u32(dst, value) } }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { unsafe { dst.write(value); } 0 }
}

/// Write one user u64; zero succeeds and one reports a fault. # C: O(1)
pub unsafe fn raw_put_user_u64(dst: *mut u64, value: u64) -> u32 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { unsafe { oxide_raw_put_user_u64(dst, value) } }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { unsafe { dst.write(value); } 0 }
}
