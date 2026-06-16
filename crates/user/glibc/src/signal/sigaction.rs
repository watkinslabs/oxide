// sigaction + signal (docs/59§6 G9, docs/54§3). The PUBLIC glibc struct
// sigaction (handler, mask[128], flags, restorer; sizeof 152) differs
// from the KERNEL struct rt_sigaction wants (handler, flags, restorer,
// mask[8]); sigaction() translates between them. x86_64 must supply
// SA_RESTORER + a trampoline that calls rt_sigreturn (the kernel pushes
// the signal frame; the handler returns through this); aarch64 uses the
// kernel vDSO restorer (no SA_RESTORER).
use super::sigset::sigset_t;

pub const SA_SIGINFO: i32 = 4;
pub const SA_RESTART: i32 = 0x1000_0000;
const SA_RESTORER: u64 = 0x0400_0000;
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;
const SIG_ERR: usize = usize::MAX;

#[repr(C)]
pub struct sigaction_t {
    pub sa_handler: usize, // union sa_handler / sa_sigaction
    pub sa_mask: sigset_t,
    pub sa_flags: i32,
    pub sa_restorer: usize,
}
// Public glibc layout (verified vs libc::sigaction in tests).
const _: () = {
    assert!(core::mem::offset_of!(sigaction_t, sa_mask) == 8);
    assert!(core::mem::offset_of!(sigaction_t, sa_flags) == 136);
    assert!(core::mem::offset_of!(sigaction_t, sa_restorer) == 144);
    assert!(core::mem::size_of::<sigaction_t>() == 152);
};

#[cfg(feature = "freestanding")]
pub mod exports {
    use super::*;
    use crate::arch::syscall::sys4;
    use crate::internal::errno::ret_isize;
    use crate::internal::nr;

    // Kernel struct sigaction (what rt_sigaction reads/writes).
    #[repr(C)]
    struct KSig { handler: usize, flags: u64, restorer: usize, mask: u64 }

    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        ".globl __restore_rt",
        ".type __restore_rt,@function",
        "__restore_rt:",
        "  mov rax, 15", // __NR_rt_sigreturn
        "  syscall",
    );
    #[cfg(target_arch = "x86_64")]
    extern "C" { fn __restore_rt(); }

    #[cfg(target_arch = "x86_64")]
    fn restorer_bits() -> (u64, usize) {
        // SAFETY of address: taking the trampoline's function address.
        (SA_RESTORER, __restore_rt as unsafe extern "C" fn() as usize)
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn restorer_bits() -> (u64, usize) { (0, 0) } // aarch64: kernel vDSO restorer

    // # C: int sigaction(int sig, const struct sigaction *act, struct sigaction *old)
    #[no_mangle]
    pub unsafe extern "C" fn sigaction(sig: i32, act: *const sigaction_t, old: *mut sigaction_t) -> i32 {
        // SAFETY: act/old are null or valid public struct sigaction; we
        // translate to the kernel layout on the stack for rt_sigaction.
        unsafe {
            let mut kact = KSig { handler: 0, flags: 0, restorer: 0, mask: 0 };
            let actp = if act.is_null() { core::ptr::null() } else {
                let (rflag, rptr) = restorer_bits();
                kact.handler = (*act).sa_handler;
                kact.flags = (*act).sa_flags as u32 as u64 | rflag;
                kact.restorer = rptr;
                kact.mask = (*act).sa_mask.__val[0];
                &kact as *const KSig
            };
            let mut kold = KSig { handler: 0, flags: 0, restorer: 0, mask: 0 };
            let oldp = if old.is_null() { core::ptr::null_mut() } else { &mut kold as *mut KSig };
            let r = ret_isize(sys4(nr::RT_SIGACTION, sig as usize, actp as usize, oldp as usize, 8)) as i32;
            if r == 0 && !old.is_null() {
                (*old).sa_handler = kold.handler;
                (*old).sa_flags = kold.flags as i32;
                (*old).sa_restorer = kold.restorer;
                (*old).sa_mask.__val = [0; 16];
                (*old).sa_mask.__val[0] = kold.mask;
            }
            r
        }
    }

    // # C: sighandler_t signal(int sig, sighandler_t handler)
    #[no_mangle]
    pub unsafe extern "C" fn signal(sig: i32, handler: usize) -> usize {
        // SAFETY: install `handler` with SA_RESTART; returns the previous
        // handler or SIG_ERR.
        unsafe {
            let act = sigaction_t { sa_handler: handler, sa_mask: sigset_t { __val: [0; 16] }, sa_flags: SA_RESTART, sa_restorer: 0 };
            let mut old = sigaction_t { sa_handler: 0, sa_mask: sigset_t { __val: [0; 16] }, sa_flags: 0, sa_restorer: 0 };
            if sigaction(sig, &act, &mut old) < 0 { return SIG_ERR; }
            old.sa_handler
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sigaction_t;
    #[test]
    fn sigaction_abi_matches_host() {
        assert_eq!(core::mem::size_of::<sigaction_t>(), core::mem::size_of::<libc::sigaction>());
        assert_eq!(core::mem::offset_of!(sigaction_t, sa_mask), core::mem::offset_of!(libc::sigaction, sa_mask));
        assert_eq!(core::mem::offset_of!(sigaction_t, sa_flags), core::mem::offset_of!(libc::sigaction, sa_flags));
        assert_eq!(core::mem::offset_of!(sigaction_t, sa_restorer), core::mem::offset_of!(libc::sigaction, sa_restorer));
    }
}
