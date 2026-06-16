// clone(2) C-library wrapper (docs/59§6 §9.1). The public glibc signature is
//   int clone(int (*fn)(void*), void *stack, int flags, void *arg,
//             pid_t *ptid, void *tls, pid_t *ctid);
// Naked function (asm body) so rustc exports it as a real cdylib symbol — a
// plain global_asm `.globl clone` is localized out of .dynsym by rustc's export
// filter. Reorders the C args into the per-arch clone syscall ABI, pushes
// fn+arg onto the caller stack; the child runs fn(arg) then exit(ret), the
// parent returns the child tid. (Distinct from pthread's __oxide_clone, which
// exits 0 and is wired for thread creation.)
#![cfg(feature = "freestanding")]
use core::ffi::c_void;

// # C: int clone(int (*fn)(void*), void *stack, int flags, void *arg, pid_t *ptid, void *tls, pid_t *ctid)
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn clone(
    _fn: extern "C" fn(*mut c_void) -> i32, _stack: *mut c_void, _flags: i32,
    _arg: *mut c_void, _ptid: *mut i32, _tls: *mut c_void, _ctid: *mut i32,
) -> i32 {
    core::arch::naked_asm!(
        "and rsi, -16",        // align child stack
        "sub rsi, 16",
        "mov [rsi], rdi",      // [sp]   = fn
        "mov [rsi+8], rcx",    // [sp+8] = arg
        "mov rdi, rdx",        // syscall arg1 = flags
        "mov rdx, r8",         // syscall arg3 = ptid
        "mov r10, [rsp+8]",    // syscall arg4 = ctid (7th C arg on the stack)
        "mov r8, r9",          // syscall arg5 = tls
        "mov eax, 56",         // SYS_clone
        "syscall",
        "test rax, rax",
        "jz 1f",               // child
        "ret",                 // parent: rax = child tid
        "1:",
        "xor ebp, ebp",
        "pop rax",             // fn
        "pop rdi",             // arg
        "call rax",            // fn(arg)
        "mov edi, eax",        // exit code = fn return
        "mov eax, 60",         // SYS_exit
        "syscall",
    )
}

// # C: int clone(...) — aarch64 (CLONE_BACKWARDS: tls before ctid)
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn clone(
    _fn: extern "C" fn(*mut c_void) -> i32, _stack: *mut c_void, _flags: i32,
    _arg: *mut c_void, _ptid: *mut i32, _tls: *mut c_void, _ctid: *mut i32,
) -> i32 {
    core::arch::naked_asm!(
        "and x1, x1, #-16",        // align child stack
        "stp x0, x3, [x1, #-16]!", // push fn,arg; x1 -> them
        "mov x0, x2",              // syscall arg1 = flags
        "mov x2, x4",              // syscall arg3 = ptid
        "mov x3, x5",              // syscall arg4 = tls
        "mov x4, x6",              // syscall arg5 = ctid
        "mov x8, #220",            // SYS_clone
        "svc #0",
        "cbz x0, 1f",              // child
        "ret",                     // parent: x0 = child tid
        "1:",
        "ldp x1, x0, [sp], #16",   // x1=fn, x0=arg
        "blr x1",                  // fn(arg)
        "mov x8, #94",             // SYS_exit
        "svc #0",
    )
}
