//! pthread — threads (docs/59§6 G11, docs/54). G11a: real thread
//! create/join via clone + a per-arch child-entry trampoline + a TLS/TCB
//! (CLONE_SETTLS) + the CHILD_CLEARTID join futex. errno stays a single
//! global until per-thread TLS lands with the rtld TLS work (G12); a note,
//! not a stub. Mutex/cond/rwlock are G11b/c.
#![cfg(feature = "freestanding")]
#![allow(clippy::upper_case_acronyms)]
pub mod mutex;
use crate::internal::nr;
use crate::malloc::heap;
use crate::posix::mman;
use core::ffi::c_void;

// CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|PARENT_SETTID|CHILD_CLEARTID
const CLONE_THREAD_FLAGS: usize = 0x3d_0f00;
const STACK_SIZE: usize = 8 << 20; // 8 MiB, glibc default
const FUTEX_WAIT: usize = 0;

type StartFn = extern "C" fn(*mut c_void) -> *mut c_void;

#[repr(C)]
pub struct Tcb {
    self_ptr: usize, // fs:0 / TPIDR self-pointer (glibc tcbhead)
    tid: i32,        // CHILD_CLEARTID word + PARENT_SETTID target
    _pad: i32,
    start: StartFn,
    arg: *mut c_void,
    retval: *mut c_void,
    stack_base: usize,
    stack_size: usize,
}

extern "C" {
    // __oxide_clone(flags, child_sp, ptid, ctid, tls) -> tid|-errno (parent);
    // in the child it runs [child_sp]=entry with [child_sp+8]=arg then exits.
    fn __oxide_clone(flags: usize, child_sp: usize, ptid: *mut i32, ctid: *mut i32, tls: usize) -> isize;
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl __oxide_clone",
    ".type __oxide_clone,@function",
    "__oxide_clone:",
    "  mov r10, rcx",        // ctid -> syscall arg4
    "  mov eax, 56",         // SYS_clone
    "  syscall",
    "  test rax, rax",
    "  jnz 2f",              // parent: return tid
    "  xor ebp, ebp",        // child: fresh frame
    "  pop rax",             // entry
    "  pop rdi",             // arg
    "  call rax",
    "  xor edi, edi",        // start returned: SYS_exit(0) (this thread only)
    "  mov eax, 60",
    "  syscall",
    "2:",
    "  ret",
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl __oxide_clone",
    ".type __oxide_clone,%function",
    "__oxide_clone:",
    "  mov x9, x3",          // ctid
    "  mov x3, x4",          // tls -> arg4 (aarch64 clone: flags,stack,ptid,tls,ctid)
    "  mov x4, x9",          // ctid -> arg5
    "  mov x8, 220",         // SYS_clone
    "  svc 0",
    "  cbnz x0, 2f",         // parent: x0=tid -> ret
    "  ldr x1, [sp]",        // entry
    "  ldr x0, [sp, 8]",     // arg
    "  add sp, sp, 16",
    "  blr x1",
    "  mov x0, 0",           // start returned: SYS_exit(0)
    "  mov x8, 93",
    "  svc 0",
    "2:",
    "  ret",
);

unsafe fn current_tcb() -> *mut Tcb {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: fs:0 holds the Tcb self-pointer on a pthread-created thread.
    unsafe { let p: usize; core::arch::asm!("mov {}, fs:0", out(reg) p); p as *mut Tcb }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: tpidr_el0 holds the Tcb self-pointer on a created thread.
    unsafe { let p: usize; core::arch::asm!("mrs {}, tpidr_el0", out(reg) p); p as *mut Tcb }
}

// The new thread's first Rust frame: run the routine, stash the result,
// then exit just this thread (CHILD_CLEARTID wakes the joiner).
extern "C" fn thread_start(tcb: *mut Tcb) {
    // SAFETY: tcb is the just-created thread's control block; we own it
    // until join. Run the user routine, then SYS_exit (this thread only).
    unsafe {
        let rv = ((*tcb).start)((*tcb).arg);
        (*tcb).retval = rv;
        crate::arch::syscall::sys1(nr::EXIT, 0);
    }
}

// # C: int pthread_create(pthread_t*, const pthread_attr_t*, start, arg)
#[no_mangle]
pub unsafe extern "C" fn pthread_create(thread: *mut usize, _attr: *const c_void, start: StartFn, arg: *mut c_void) -> i32 {
    // SAFETY: thread is a writable pthread_t out-param; we mmap a stack +
    // TCB and clone a CLONE_THREAD child into thread_start.
    unsafe {
        let base = mman::mmap(core::ptr::null_mut(), STACK_SIZE, mman::PROT_READ | mman::PROT_WRITE, mman::MAP_PRIVATE | mman::MAP_ANONYMOUS, -1, 0);
        if base == usize::MAX as *mut u8 { return 11; } // EAGAIN
        mman::mprotect(base, 4096, 0); // guard page (PROT_NONE)
        let tcb = heap::malloc(core::mem::size_of::<Tcb>()) as *mut Tcb;
        if tcb.is_null() { mman::munmap(base, STACK_SIZE); return 11; }
        (*tcb).self_ptr = tcb as usize;
        (*tcb).tid = 0;
        (*tcb).start = start;
        (*tcb).arg = arg;
        (*tcb).retval = core::ptr::null_mut();
        (*tcb).stack_base = base as usize;
        (*tcb).stack_size = STACK_SIZE;
        // child stack: 16-aligned, with [sp]=entry, [sp+8]=arg(tcb)
        let sp = ((base as usize + STACK_SIZE) & !15) - 16;
        *(sp as *mut usize) = thread_start as extern "C" fn(*mut Tcb) as usize;
        *((sp + 8) as *mut usize) = tcb as usize;
        let r = __oxide_clone(CLONE_THREAD_FLAGS, sp, &mut (*tcb).tid, &mut (*tcb).tid, tcb as usize);
        if r < 0 {
            mman::munmap(base, STACK_SIZE);
            heap::free(tcb as *mut u8);
            return -r as i32;
        }
        *thread = tcb as usize;
        0
    }
}

// # C: int pthread_join(pthread_t, void **retval)
#[no_mangle]
pub unsafe extern "C" fn pthread_join(thread: usize, retval: *mut *mut c_void) -> i32 {
    // SAFETY: thread is a joinable pthread_t from pthread_create; wait on
    // the CHILD_CLEARTID futex word, then reclaim the stack + TCB.
    unsafe {
        let tcb = thread as *mut Tcb;
        let addr = &mut (*tcb).tid as *mut i32;
        loop {
            let t = core::ptr::read_volatile(addr);
            if t == 0 { break; }
            crate::arch::syscall::sys6(nr::FUTEX, addr as usize, FUTEX_WAIT, t as usize, 0, 0, 0);
        }
        if !retval.is_null() { *retval = (*tcb).retval; }
        mman::munmap((*tcb).stack_base as *mut u8, (*tcb).stack_size);
        heap::free(tcb as *mut u8);
        0
    }
}

// # C: pthread_t pthread_self(void)
#[no_mangle]
pub unsafe extern "C" fn pthread_self() -> usize {
    // SAFETY: returns the current thread's TCB via the thread pointer
    // (valid on pthread-created threads; main-thread TCB lands with G12 TLS).
    unsafe { current_tcb() as usize }
}

// # C: _Noreturn void pthread_exit(void *retval)
#[no_mangle]
pub unsafe extern "C" fn pthread_exit(retval: *mut c_void) -> ! {
    // SAFETY: stash retval in this thread's TCB, then SYS_exit this thread.
    unsafe {
        let tcb = current_tcb();
        if !tcb.is_null() { (*tcb).retval = retval; }
        crate::arch::syscall::sys1(nr::EXIT, 0);
        core::hint::unreachable_unchecked()
    }
}

// # C: int pthread_detach(pthread_t) — best-effort (no auto-reap yet)
#[no_mangle]
pub unsafe extern "C" fn pthread_detach(_thread: usize) -> i32 { 0 }

// # C: int pthread_equal(pthread_t a, pthread_t b)
#[no_mangle]
pub extern "C" fn pthread_equal(a: usize, b: usize) -> i32 { (a == b) as i32 }
