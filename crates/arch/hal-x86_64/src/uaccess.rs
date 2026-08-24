#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(r#"
    .global oxide_raw_copy_from_user
    .type oxide_raw_copy_from_user, @function
oxide_raw_copy_from_user:
    mov rcx, rdx
1:  rep movsb
    xor eax, eax
    ret
2:  mov rax, rcx
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 1b - .
    .long 2b - .
    .popsection
    .size oxide_raw_copy_from_user, . - oxide_raw_copy_from_user

    .global oxide_raw_copy_to_user
    .type oxide_raw_copy_to_user, @function
oxide_raw_copy_to_user:
    mov rcx, rdx
3:  rep movsb
    xor eax, eax
    ret
4:  mov rax, rcx
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 3b - .
    .long 4b - .
    .popsection
    .size oxide_raw_copy_to_user, . - oxide_raw_copy_to_user

    .global oxide_raw_cmpxchg_user_u32
    .type oxide_raw_cmpxchg_user_u32, @function
oxide_raw_cmpxchg_user_u32:
    mov eax, esi
5:  lock cmpxchg dword ptr [rdi], edx
    mov dword ptr [rcx], eax
    xor eax, eax
    ret
6:  mov eax, 1
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 5b - .
    .long 6b - .
    .popsection
    .size oxide_raw_cmpxchg_user_u32, . - oxide_raw_cmpxchg_user_u32

    .global oxide_raw_get_user_u32
    .type oxide_raw_get_user_u32, @function
oxide_raw_get_user_u32:
1:  mov eax, dword ptr [rdi]
    mov dword ptr [rsi], eax
    xor eax, eax
    ret
2:  mov eax, 1
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 1b - .
    .long 2b - .
    .popsection
    .size oxide_raw_get_user_u32, . - oxide_raw_get_user_u32

    .global oxide_raw_get_user_u64
    .type oxide_raw_get_user_u64, @function
oxide_raw_get_user_u64:
3:  mov rax, qword ptr [rdi]
    mov qword ptr [rsi], rax
    xor eax, eax
    ret
4:  mov eax, 1
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 3b - .
    .long 4b - .
    .popsection
    .size oxide_raw_get_user_u64, . - oxide_raw_get_user_u64

    .global oxide_raw_put_user_u32
    .type oxide_raw_put_user_u32, @function
oxide_raw_put_user_u32:
5:  mov dword ptr [rdi], esi
    xor eax, eax
    ret
6:  mov eax, 1
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 5b - .
    .long 6b - .
    .popsection
    .size oxide_raw_put_user_u32, . - oxide_raw_put_user_u32

    .global oxide_raw_put_user_u64
    .type oxide_raw_put_user_u64, @function
oxide_raw_put_user_u64:
7:  mov qword ptr [rdi], rsi
    xor eax, eax
    ret
8:  mov eax, 1
    ret
    .pushsection __ex_table,"a"
    .balign 8
    .long 7b - .
    .long 8b - .
    .popsection
    .size oxide_raw_put_user_u64, . - oxide_raw_put_user_u64
"#);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
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
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: caller supplies nonoverlapping spans; asm returns uncopied bytes after extable recovery.
        unsafe { oxide_raw_copy_from_user(dst, src, len) }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    {
        // SAFETY: hosted caller supplies valid nonoverlapping spans.
        unsafe { core::ptr::copy_nonoverlapping(src, dst, len); }
        0
    }
}

/// Copy to user and return bytes not copied. # C: O(len + page faults)
pub unsafe fn raw_copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: caller supplies nonoverlapping spans; asm returns uncopied bytes after extable recovery.
        unsafe { oxide_raw_copy_to_user(dst, src, len) }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    {
        // SAFETY: hosted caller supplies valid nonoverlapping spans.
        unsafe { core::ptr::copy_nonoverlapping(src, dst, len); }
        0
    }
}

/// Atomically replace a user word; 0 succeeds and 1 reports a fault. # C: O(page faults)
pub unsafe fn raw_cmpxchg_user_u32(uaddr: *mut u32, old: u32, new: u32, seen: *mut u32) -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: caller supplies a user word and live output; asm recovers the faultable RMW through its extable entry.
        unsafe { oxide_raw_cmpxchg_user_u32(uaddr, old, new, seen) }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
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
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { unsafe { oxide_raw_get_user_u32(src, out) } }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { unsafe { out.write(src.read()); } 0 }
}

/// Read one user u64; zero succeeds and one reports a fault. # C: O(1)
pub unsafe fn raw_get_user_u64(src: *const u64, out: *mut u64) -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { unsafe { oxide_raw_get_user_u64(src, out) } }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { unsafe { out.write(src.read()); } 0 }
}

/// Write one user u32; zero succeeds and one reports a fault. # C: O(1)
pub unsafe fn raw_put_user_u32(dst: *mut u32, value: u32) -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { unsafe { oxide_raw_put_user_u32(dst, value) } }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { unsafe { dst.write(value); } 0 }
}

/// Write one user u64; zero succeeds and one reports a fault. # C: O(1)
pub unsafe fn raw_put_user_u64(dst: *mut u64, value: u64) -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { unsafe { oxide_raw_put_user_u64(dst, value) } }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { unsafe { dst.write(value); } 0 }
}
