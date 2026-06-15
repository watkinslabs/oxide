// _start — process entry (crt1.o equivalent, docs/59§6 G2). The kernel
// hands control here with the initial stack: [argc][argv0..][NULL][envp..]
// [NULL][auxv..]. We zero the frame pointer, marshal the SysV args, align
// the stack, and call __libc_start_main(main, argc, argv, init, fini,
// rtld_fini, stack_end). It never returns.
//
// `main` is the app's symbol, resolved at link. Built only into the
// shipped artifact (freestanding). Rust global_asm! is Intel syntax.

// x86_64 SysV: args rdi,rsi,rdx,rcx,r8,r9 then stack. main→rdi, argc→rsi,
// argv→rdx, init/fini/rtld_fini=0, stack_end on the stack.
#[cfg(all(feature = "freestanding", target_arch = "x86_64"))]
core::arch::global_asm!(
    ".text",
    ".globl _start",
    ".type _start,@function",
    "_start:",
    "  xor ebp, ebp",            // outermost frame: fp = 0
    "  mov rsi, [rsp]",          // argc
    "  lea rdx, [rsp+8]",        // argv (PIE/non-PIE safe)
    "  lea rdi, [rip+main]",     // &main
    "  xor ecx, ecx",            // init = 0
    "  xor r8d, r8d",            // fini = 0
    "  xor r9d, r9d",            // rtld_fini = 0
    "  mov rax, rsp",            // stack_end = entry rsp
    "  and rsp, -16",            // 16-align
    "  sub rsp, 8",              // keep rsp%16==0 across the next push
    "  push rax",                // 7th arg: stack_end
    "  call __libc_start_main",
    "  ud2",                     // unreachable
    ".size _start, .-_start",
);

// aarch64: 8 arg regs, so stack_end rides in x6 (no stack arg).
#[cfg(all(feature = "freestanding", target_arch = "aarch64"))]
core::arch::global_asm!(
    ".text",
    ".globl _start",
    ".type _start,%function",
    "_start:",
    "  mov x29, 0",              // frame pointer = 0
    "  mov x30, 0",              // link register = 0
    "  ldr x1, [sp]",           // argc
    "  add x2, sp, 8",          // argv
    "  adrp x0, main",          // &main
    "  add x0, x0, :lo12:main",
    "  mov x6, sp",             // stack_end
    "  mov x3, 0",              // init
    "  mov x4, 0",              // fini
    "  mov x5, 0",              // rtld_fini
    "  mov x7, sp",             // 16-align via scratch (sp not an AND operand)
    "  and x7, x7, -16",
    "  mov sp, x7",
    "  bl __libc_start_main",
    "  brk 0",                  // unreachable
    ".size _start, .-_start",
);
