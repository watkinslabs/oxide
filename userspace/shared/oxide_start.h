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
__asm__ (
    ".global _start\n\t"
    ".type   _start, %function\n\t"
    "_start:\n\t"
    "    ldr  x0, [sp]\n\t"               // argc
    "    add  x1, sp, #8\n\t"             // argv
    "    add  x2, x1, x0, lsl #3\n\t"     // argv + argc*8
    "    add  x2, x2, #8\n\t"             // envp
    "    bl   main\n\t"
    "    mov  w8, #93\n\t"                // SYS_exit (aarch64)
    "    svc  #0\n\t"
    "    brk  #0\n\t"
);
#else
#error "oxide_start.h: unsupported architecture"
#endif

#endif // OXIDE_START_H
