#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
core::arch::global_asm!(r#"
    .global oxide_raw_copy_from_user
    .type oxide_raw_copy_from_user, %function
oxide_raw_copy_from_user:
    cbz x2, 3f
1:  ldrb w3, [x1], #1
2:  strb w3, [x0], #1
    subs x2, x2, #1
    b.ne 1b
3:  mov x0, #0
    ret
4:  mov x0, x2
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 1b - .
    .long 4b - .
    .long 2b - .
    .long 4b - .
    .popsection
    .size oxide_raw_copy_from_user, . - oxide_raw_copy_from_user

    .global oxide_raw_copy_to_user
    .type oxide_raw_copy_to_user, %function
oxide_raw_copy_to_user:
    cbz x2, 7f
5:  ldrb w3, [x1], #1
6:  strb w3, [x0], #1
    subs x2, x2, #1
    b.ne 5b
7:  mov x0, #0
    ret
8:  mov x0, x2
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 5b - .
    .long 8b - .
    .long 6b - .
    .long 8b - .
    .popsection
    .size oxide_raw_copy_to_user, . - oxide_raw_copy_to_user
"#);

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_raw_copy_from_user(dst: *mut u8, src: *const u8, len: usize) -> usize;
    fn oxide_raw_copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> usize;
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
