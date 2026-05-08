// Portable static-PIE _start for arch-portable userspace bins.
//
// Usage in any userspace .c file:
//
//   #include "shared/oxide_start.h"
//   int main(int argc, char** argv, char** envp) { ... }
//
// The header emits a per-arch _start (file-scope inline asm so the
// compiler's prologue can't reshape the stack) that reads
// argc/argv/envp from the SysV initial stack, calls main, and
// feeds the return value to _exit(). Both x86_64 and aarch64.
//
// Built with `-static-pie -fPIE -O2 -nostartfiles`. main() is a
// regular C function the linker resolves into the asm `bl main`;
// -nostartfiles suppresses musl's normal crt1, which is fine for
// short-lived utilities that don't need atexit / stdio init.

#ifndef OXIDE_START_H
#define OXIDE_START_H

#include <unistd.h>

extern int main(int argc, char** argv, char** envp);

#if defined(__x86_64__)
__asm__ (
    ".global _start\n\t"
    ".type   _start, @function\n\t"
    "_start:\n\t"
    "    mov  (%rsp), %rdi\n\t"           // argc
    "    lea  8(%rsp), %rsi\n\t"          // argv
    "    lea  8(%rsi,%rdi,8), %rdx\n\t"   // envp
    "    and  $-16, %rsp\n\t"
    "    call main\n\t"
    "    mov  %eax, %edi\n\t"
    "    mov  $60, %eax\n\t"              // SYS_exit
    "    syscall\n\t"
    "    ud2\n\t"
);
#elif defined(__aarch64__)
// musl-aarch64 keeps PAGE_SIZE in the runtime `__libc` struct
// (offset 0x30) rather than as a compile-time constant. Library
// functions like mprotect/mmap mask address+len with -__libc.page_size;
// uninitialised it's 0 and every alignment becomes 0. Since we
// build with -nostartfiles, musl's __init_libc never runs and
// the field stays 0 unless we seed it. `oxide_libc_init` (defined
// below) writes 4096 there before main runs.
//
// The init has to be a real C call — inline-asm `adrp __libc; str`
// links fine but musl's __libc lives in a section whose first-touch
// fault path needs a fully-initialised user TLS / SP_EL0 / kernel
// frame, and on our v1 ELF loader the very first user-mode write
// from _start mis-translates before the demand-fault handler can
// install the BSS page. Routing through a C function gives the
// compiler a chance to emit the proper PIE-safe sequence (which
// uses GOT and the kernel's R_AARCH64_RELATIVE pass already wires
// the GOT entry to the right runtime address).
extern void oxide_libc_init(void);
__asm__ (
    ".global _start\n\t"
    ".type   _start, %function\n\t"
    "_start:\n\t"
    "    ldr  x0, [sp]\n\t"               // argc
    "    add  x1, sp, #8\n\t"             // argv
    "    add  x2, x1, x0, lsl #3\n\t"     // argv + argc*8
    "    add  x2, x2, #8\n\t"             // envp
    "    stp  x0, x1, [sp, #-32]!\n\t"
    "    str  x2,     [sp, #16]\n\t"
    "    bl   oxide_libc_init\n\t"
    "    ldr  x2,     [sp, #16]\n\t"
    "    ldp  x0, x1, [sp], #32\n\t"
    "    bl   main\n\t"
    "    mov  w8, #93\n\t"                // SYS_exit (aarch64)
    "    svc  #0\n\t"
    "    brk  #0\n\t"
);

// Forward-decl matching musl's `struct __libc` enough to reach the
// page_size field at offset 0x30. We don't include any struct body
// — just declare it as bytes plus the field at the known offset.
struct __oxide_libc_shim {
    char _pad[0x30];
    unsigned long page_size;
};
extern struct __oxide_libc_shim __libc;
__attribute__((noinline))
void oxide_libc_init(void) {
    __libc.page_size = 4096;
}
#else
#error "oxide_start.h: unsupported architecture"
#endif

#endif // OXIDE_START_H
