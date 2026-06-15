//! setjmp — non-local jumps (docs/59§6 G17d). glibc `__jmp_buf_tag`
//! { __jmpbuf[arch], __mask_was_saved, __saved_mask }. The register save/
//! restore is per-arch global_asm (x86_64.rs / aarch64.rs); the signal-mask
//! save/restore + val normalisation are Rust helpers. setjmp/_setjmp do NOT
//! save the mask (glibc semantics); sigsetjmp(env, savesigs!=0) does.
//! jmp_buf size ABI-checked vs the libc crate.
#![allow(non_camel_case_types)] // C ABI type names

#[cfg(target_arch = "x86_64")]
pub const JB_LEN: usize = 8; // rbx,rbp,r12,r13,r14,r15,rsp,rip
#[cfg(target_arch = "aarch64")]
pub const JB_LEN: usize = 22; // x19-x28,x29,x30,sp,d8-d15 (+pad)

/// __sigset_t — 1024-bit kernel-compatible mask (only the first 8 bytes are
/// touched by rt_sigprocmask).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct __sigset_t { __val: [u64; 16] }

#[repr(C)]
pub struct __jmp_buf_tag {
    __jmpbuf: [u64; JB_LEN],
    __mask_was_saved: i32,
    __saved_mask: __sigset_t,
}

/// `jmp_buf` / `sigjmp_buf` are a 1-element array of the tag (C array decay →
/// the functions take `*mut __jmp_buf_tag`).
pub type jmp_buf = [__jmp_buf_tag; 1];

#[cfg(all(feature = "freestanding", target_arch = "x86_64"))]
mod x86_64;
#[cfg(all(feature = "freestanding", target_arch = "aarch64"))]
mod aarch64;

#[cfg(feature = "freestanding")]
mod imp {
    use super::__jmp_buf_tag;
    use crate::arch::syscall::sys4;
    use crate::internal::nr;

    const SIG_SETMASK: usize = 2;
    const KERNEL_SIGSET: usize = 8; // kernel sigset_t bytes

    extern "C" {
        // register restore + jump (per-arch asm); never returns.
        fn __longjmp_regs(env: *mut __jmp_buf_tag, val: i32) -> !;
    }

    // Field addresses within the tag (no deref; addr_of_mut on a raw pointer).
    fn mask_ptr(env: *mut __jmp_buf_tag) -> usize {
        // SAFETY: env is a valid jmp_buf pointer; take the address of its
        // __saved_mask field without forming a reference (no read/write).
        unsafe { core::ptr::addr_of_mut!((*env).__saved_mask) as usize }
    }
    fn flag_ptr(env: *mut __jmp_buf_tag) -> *mut i32 {
        // SAFETY: env is a valid jmp_buf pointer; take the address of its
        // __mask_was_saved field without forming a reference (no read/write).
        unsafe { core::ptr::addr_of_mut!((*env).__mask_was_saved) }
    }

    /// Tail-called by the setjmp asm after registers are saved. Saves the
    /// signal mask when `savemask` is set, then returns 0 (the direct return).
    /// # C: int __sigjmp_save(jmp_buf, int savemask)
    #[no_mangle]
    pub unsafe extern "C" fn __sigjmp_save(env: *mut __jmp_buf_tag, savemask: i32) -> i32 {
        // SAFETY: env is a valid jmp_buf written by the setjmp asm; read the
        // current blocked mask into its __saved_mask (first 8 bytes) when asked.
        unsafe {
            if savemask != 0 {
                sys4(nr::RT_SIGPROCMASK, 0, 0, mask_ptr(env), KERNEL_SIGSET); // how=SIG_BLOCK, set=NULL → query
                *flag_ptr(env) = 1;
            } else {
                *flag_ptr(env) = 0;
            }
            0
        }
    }

    unsafe fn restore_mask(env: *mut __jmp_buf_tag) {
        // SAFETY: env is a valid jmp_buf; if a mask was saved, install it.
        unsafe {
            if *flag_ptr(env) != 0 {
                sys4(nr::RT_SIGPROCMASK, SIG_SETMASK, mask_ptr(env), 0, KERNEL_SIGSET);
            }
        }
    }

    fn norm(val: i32) -> i32 { if val == 0 { 1 } else { val } } // longjmp(env,0) → 1

    // # C: void longjmp(jmp_buf env, int val)
    #[no_mangle]
    pub unsafe extern "C" fn longjmp(env: *mut __jmp_buf_tag, val: i32) -> ! {
        // SAFETY: env was initialised by a setjmp that has not yet returned out
        // of scope; restore registers (no mask) and resume at its return point.
        unsafe { __longjmp_regs(env, norm(val)) }
    }

    // # C: void siglongjmp(sigjmp_buf env, int val)
    #[no_mangle]
    pub unsafe extern "C" fn siglongjmp(env: *mut __jmp_buf_tag, val: i32) -> ! {
        // SAFETY: env initialised by sigsetjmp; restore the saved signal mask
        // (if any) then registers, resuming at the sigsetjmp return point.
        unsafe { restore_mask(env); __longjmp_regs(env, norm(val)) }
    }
}

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;
    // glibc sizeof(jmp_buf): x86_64 = 8*8 + 4 + pad4 + 128 = 200;
    // aarch64 = 22*8 + 4 + pad4 + 128 = 312. (libc crate does not export the
    // jmp_buf type, so the constant is checked directly.)
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn jmp_buf_abi_x86() { assert_eq!(core::mem::size_of::<jmp_buf>(), 200); }
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn jmp_buf_abi_arm() { assert_eq!(core::mem::size_of::<jmp_buf>(), 312); }
}
