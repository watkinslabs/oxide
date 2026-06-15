//! crt1 — process entry object for dynamically-linked executables (docs/59§6
//! G19a). Same `_start` as glibc's `start::entry` but shipped as a standalone
//! object (Scrt1.o role) so a normal `main`-based program links dynamically
//! against libc.so.6 (which provides `__libc_start_main`) without pulling the
//! whole static libc.a. PIC so it works in a PIE. `xtask sysroot` extracts the
//! object from this crate's archive into lib/Scrt1.o.
#![no_std]

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

// x86_64 SysV: main→rdi, argc→rsi, argv→rdx, init/fini/rtld_fini=0,
// stack_end pushed as the 7th arg. `call __libc_start_main` resolves through
// the PLT to libc.so.6; `lea [rip+main]` is PC-relative to the app's main.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".text",
    ".globl _start",
    ".type _start,@function",
    "_start:",
    "  xor ebp, ebp",
    "  mov rsi, [rsp]",          // argc
    "  lea rdx, [rsp+8]",        // argv
    "  lea rdi, [rip+main]",     // &main
    "  xor ecx, ecx",            // init = 0
    "  xor r8d, r8d",            // fini = 0
    "  xor r9d, r9d",            // rtld_fini = 0
    "  mov rax, rsp",            // stack_end
    "  and rsp, -16",
    "  sub rsp, 8",
    "  push rax",
    "  call __libc_start_main",
    "  ud2",
    ".size _start, .-_start",
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".text",
    ".globl _start",
    ".type _start,%function",
    "_start:",
    "  mov x29, 0",
    "  mov x30, 0",
    "  ldr x1, [sp]",           // argc
    "  add x2, sp, 8",          // argv
    "  adrp x0, main",          // &main
    "  add x0, x0, :lo12:main",
    "  mov x6, sp",             // stack_end
    "  mov x3, 0",
    "  mov x4, 0",
    "  mov x5, 0",
    "  mov x7, sp",
    "  and x7, x7, -16",
    "  mov sp, x7",
    "  bl __libc_start_main",
    "  brk 0",
    ".size _start, .-_start",
);
