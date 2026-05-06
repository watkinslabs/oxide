// PID 1: real-musl static-PIE init.
//
// Built via `musl-gcc -static-pie -fPIE -O2 -nostartfiles`.
//
// Boot chain:
//   1. Print "oxide init: hello\n".
//   2. Try execve("/sbin/svcd", argv=["svcd"], envp=[]) — if svcd
//      exists, hand off the supervision job.
//   3. Fallback: respawn /bin/sh in a loop (legacy P5 behavior),
//      capped at 8 iterations to avoid runaway when sh refuses
//      to start.

#include <sys/syscall.h>
#include <unistd.h>

static long sc1(long n, long a) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a) : "rcx","r11","memory"); return r;
}
static long sc3(long n, long a, long b, long c) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx","r11","memory"); return r;
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    static const char hello[] = "oxide init: hello from real-musl PID 1\n";
    sc3(SYS_write, 1, (long)hello, sizeof(hello) - 1);

    // Try to hand off to svcd. If it isn't installed (or exec fails)
    // we fall through to the legacy shell-respawn loop.
    {
        static char* argv[] = { "svcd", 0 };
        static char* envp[] = { 0 };
        sc3(SYS_execve, (long)"/sbin/svcd", (long)argv, (long)envp);
        // If we get here, exec failed; carry on with the fallback.
        static const char no_svcd[] = "init: /sbin/svcd not present, falling back to shell respawn\n";
        sc3(SYS_write, 1, (long)no_svcd, sizeof(no_svcd) - 1);
    }

    for (int i = 0; i < 8; i++) {
        long pid;
        __asm__ volatile (
            "syscall" : "=a"(pid)
            : "0"((long)SYS_fork), "D"(0)
            : "rcx", "r11", "memory");
        if (pid == 0) {
            sc3(SYS_execve, (long)"/bin/sh", 0, 0);
            static const char fail[] = "init: exec /bin/sh failed\n";
            sc3(SYS_write, 1, (long)fail, sizeof(fail) - 1);
            sc3(SYS_exit, 1, 0, 0);
            __builtin_unreachable();
        }
        long r;
        register long r10 __asm__("r10") = 0;
        __asm__ volatile (
            "syscall" : "=a"(r)
            : "0"((long)SYS_wait4), "D"(pid), "S"(0), "d"(0), "r"(r10)
            : "rcx", "r11", "memory");
    }
    sc3(SYS_exit, 0, 0, 0);
    __builtin_unreachable();
}
