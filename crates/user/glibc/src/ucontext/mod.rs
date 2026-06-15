//! ucontext — <ucontext.h> user-level context switching (docs/59§6, §54).
//! getcontext/setcontext save and restore the callee-saved register set, SP,
//! PC, and the signal mask (via rt_sigprocmask). makecontext lays out a fresh
//! stack with an entry fn, its args, and a return link to uc_link. swapcontext
//! is getcontext(cur) then setcontext(next). The register save is per-arch
//! naked asm (x86_64.rs / aarch64.rs) — naked #[no_mangle] so rustc exports the
//! symbol from libc.so.6 (raw global_asm symbols get localized by the version
//! script; see setjmp/x86_64.rs). ucontext_t / mcontext_t MUST match host
//! glibc per-arch (ABI-checked in tests).
#![allow(non_camel_case_types)] // C ABI type names

use crate::signal::sigset::sigset_t;

/// stack_t — <signal.h> alternate-stack descriptor (also uc_stack).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct stack_t {
    pub ss_sp: *mut core::ffi::c_void,
    pub ss_flags: i32,
    pub ss_size: usize,
}

// ---- x86_64 ucontext_t / mcontext_t (host glibc layout) ----
// gregset_t = [i64; 23]; gregs at uc_mcontext+0 (uc_mcontext at ucontext+40).
// Register-slot indices into gregs (glibc REG_*).
#[cfg(target_arch = "x86_64")]
pub mod regidx {
    pub const R8: usize = 0;
    pub const R9: usize = 1;
    pub const R12: usize = 4;
    pub const R13: usize = 5;
    pub const R14: usize = 6;
    pub const R15: usize = 7;
    pub const RDI: usize = 8;
    pub const RSI: usize = 9;
    pub const RBP: usize = 10;
    pub const RBX: usize = 11;
    pub const RDX: usize = 12;
    pub const RCX: usize = 14;
    pub const RSP: usize = 15;
    pub const RIP: usize = 16;
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct mcontext_t {
    pub gregs: [i64; 23],
    pub fpregs: *mut core::ffi::c_void,
    pub __reserved1: [u64; 8],
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct ucontext_t {
    pub uc_flags: u64,
    pub uc_link: *mut ucontext_t,
    pub uc_stack: stack_t,
    pub uc_mcontext: mcontext_t,
    pub uc_sigmask: sigset_t,
    // glibc trails the mcontext fpregs save area (_libc_fpstate, 512 bytes).
    pub __fpregs_mem: [u64; 64],
    pub __ssp: [u64; 4],
}

// ---- aarch64 ucontext_t / mcontext_t (host glibc layout) ----
// mcontext = kernel struct sigcontext: fault_address, regs[31], sp, pc,
// pstate, __reserved[4096] (holds fpsimd_context). uc order: flags, link,
// stack, sigmask, mcontext.
#[cfg(target_arch = "aarch64")]
#[repr(C, align(16))]
pub struct mcontext_t {
    pub fault_address: u64,
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub __reserved: [u8; 4096],
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
pub struct ucontext_t {
    pub uc_flags: u64,
    pub uc_link: *mut ucontext_t,
    pub uc_stack: stack_t,
    pub uc_sigmask: sigset_t,
    pub uc_mcontext: mcontext_t,
}

// Non-target host build (workspace rlib type-check): minimal placeholder so
// the module compiles; never linked into a running binary on a non-Linux arch.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[repr(C)]
pub struct mcontext_t {
    pub __opaque: [u64; 32],
}
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[repr(C)]
pub struct ucontext_t {
    pub uc_flags: u64,
    pub uc_link: *mut ucontext_t,
    pub uc_stack: stack_t,
    pub uc_mcontext: mcontext_t,
    pub uc_sigmask: sigset_t,
}

#[cfg(all(feature = "freestanding", target_arch = "x86_64"))]
mod x86_64;
#[cfg(all(feature = "freestanding", target_arch = "aarch64"))]
mod aarch64;

#[cfg(all(feature = "freestanding", target_arch = "x86_64"))]
use x86_64::arch_makecontext;
#[cfg(all(feature = "freestanding", target_arch = "aarch64"))]
use aarch64::arch_makecontext;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::arch::syscall::sys4;
    use crate::internal::nr;

    const SIG_SETMASK: usize = 2;
    const KERNEL_SIGSET: usize = 8; // kernel sigset_t bytes touched by the syscall

    extern "C" {
        // Per-arch register restore + jump to uc_mcontext PC; never returns.
        fn __setcontext_regs(ucp: *const ucontext_t) -> !;
        // Per-arch register save into uc_mcontext; tail-calls __getcontext_post.
        fn getcontext(ucp: *mut ucontext_t) -> i32;
    }

    fn mask_ptr(ucp: *mut ucontext_t) -> usize {
        // SAFETY: ucp is a valid ucontext_t pointer; take the address of its
        // uc_sigmask field without forming a reference (no read/write).
        unsafe { core::ptr::addr_of_mut!((*ucp).uc_sigmask) as usize }
    }
    fn mask_ptr_const(ucp: *const ucontext_t) -> usize {
        // SAFETY: ucp is a valid ucontext_t pointer; take the address of its
        // uc_sigmask field without forming a reference (read-only by caller).
        unsafe { core::ptr::addr_of!((*ucp).uc_sigmask) as usize }
    }

    /// Tail-called by the getcontext asm after registers are saved. Fills
    /// uc_sigmask with the current blocked mask and returns 0 (the direct
    /// return path of getcontext).
    /// # C: int __getcontext_post(ucontext_t *ucp)
    #[no_mangle]
    pub unsafe extern "C" fn __getcontext_post(ucp: *mut ucontext_t) -> i32 {
        // SAFETY: ucp is a valid ucontext_t written by the getcontext asm;
        // query the current blocked signal mask into its uc_sigmask
        // (how=SIG_BLOCK, set=NULL → query) per rt_sigprocmask(2).
        unsafe { sys4(nr::RT_SIGPROCMASK, 0, 0, mask_ptr(ucp), KERNEL_SIGSET); }
        0
    }

    /// # C: int setcontext(const ucontext_t *ucp)
    #[no_mangle]
    pub unsafe extern "C" fn setcontext(ucp: *const ucontext_t) -> i32 {
        // SAFETY: ucp is a valid ucontext_t initialised by getcontext or
        // makecontext; install its saved signal mask then restore registers
        // and jump to its PC (never returns down this path).
        unsafe {
            sys4(nr::RT_SIGPROCMASK, SIG_SETMASK, mask_ptr_const(ucp), 0, KERNEL_SIGSET);
            __setcontext_regs(ucp);
        }
    }

    /// # C: int swapcontext(ucontext_t *oucp, const ucontext_t *ucp)
    #[no_mangle]
    pub unsafe extern "C" fn swapcontext(oucp: *mut ucontext_t, ucp: *const ucontext_t) -> i32 {
        // getcontext(oucp) saves the current context (returns 0 now AND when later
        // resumed via oucp — indistinguishable by return value); a guard stored IN
        // oucp->uc_flags, read/written volatile so the compiler reloads it after the
        // resume jump, disambiguates: first pass sees 0 and calls setcontext(ucp),
        // the resume pass sees 1 and returns.
        // SAFETY: oucp/ucp are valid distinct ucontext_t; guard lives in oucp->uc_flags.
        unsafe {
            let guard = core::ptr::addr_of_mut!((*oucp).uc_flags);
            core::ptr::write_volatile(guard, 0);
            if getcontext(oucp) != 0 { return -1; }
            if core::ptr::read_volatile(guard) == 0 {
                core::ptr::write_volatile(guard, 1);
                setcontext(ucp);
            }
            0
        }
    }

    /// # C: void makecontext(ucontext_t *ucp, void (*func)(void), int argc, ...)
    /// Lay out ucp->uc_stack as the running stack for `func`, passing up to 6
    /// integer args, with a return that flows into uc_link (or exits when
    /// uc_link is NULL). getcontext(ucp) must have been called first.
    #[no_mangle]
    pub unsafe extern "C" fn makecontext(
        ucp: *mut ucontext_t,
        func: extern "C" fn(),
        _argc: i32,
        a1: usize, a2: usize, a3: usize,
        a4: usize, a5: usize, a6: usize,
    ) {
        // SAFETY: ucp is a getcontext-initialised ucontext_t with uc_stack set
        // to a writable region; we compute the aligned stack top, plant the
        // entry PC, the integer args, and a trampoline that calls setcontext on
        // uc_link when func returns. Per-arch via super:: helpers.
        unsafe { super::arch_makecontext(ucp, func, [a1, a2, a3, a4, a5, a6]); }
    }
}

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;
    // ucontext_t / stack_t ABI vs host glibc. stack_t is identical on both
    // arches; ucontext_t/mcontext_t sizes checked on the matching host arch.
    #[test]
    fn stack_t_abi() {
        assert_eq!(core::mem::size_of::<stack_t>(), core::mem::size_of::<libc::stack_t>());
        assert_eq!(core::mem::offset_of!(stack_t, ss_sp), core::mem::offset_of!(libc::stack_t, ss_sp));
        assert_eq!(core::mem::offset_of!(stack_t, ss_flags), core::mem::offset_of!(libc::stack_t, ss_flags));
        assert_eq!(core::mem::offset_of!(stack_t, ss_size), core::mem::offset_of!(libc::stack_t, ss_size));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ucontext_abi_x86() {
        // host glibc x86_64: uc_link@8, uc_stack@16, uc_mcontext@40,
        // uc_sigmask@296, sizeof 968.
        assert_eq!(core::mem::offset_of!(ucontext_t, uc_link), 8);
        assert_eq!(core::mem::offset_of!(ucontext_t, uc_stack), 16);
        assert_eq!(core::mem::offset_of!(ucontext_t, uc_mcontext), 40);
        assert_eq!(core::mem::offset_of!(ucontext_t, uc_sigmask), 296);
        assert_eq!(core::mem::size_of::<ucontext_t>(), 968);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn ucontext_abi_arm() {
        // host glibc aarch64: uc_link@8, uc_stack@16, uc_sigmask@40,
        // uc_mcontext@176 (after 128-byte sigmask + 8 align pad), regs@8.
        assert_eq!(core::mem::offset_of!(ucontext_t, uc_link), 8);
        assert_eq!(core::mem::offset_of!(ucontext_t, uc_stack), 16);
        assert_eq!(core::mem::offset_of!(ucontext_t, uc_sigmask), 40);
        assert_eq!(core::mem::offset_of!(ucontext_t, uc_mcontext), 176);
        assert_eq!(core::mem::offset_of!(mcontext_t, regs), 8);
        assert_eq!(core::mem::offset_of!(mcontext_t, sp), 256);
        assert_eq!(core::mem::offset_of!(mcontext_t, pc), 264);
    }
}
