// Phase 5 PID 1: minimal real-musl static-PIE init.
//
// Built via `musl-gcc -static-pie -fPIE -O2 -nostartfiles`. First
// non-hand-synthesized binary the kernel runs as /init. Validates
// the full ELF loader → execve → musl-startup → user-syscall
// path against a real toolchain output instead of the
// build_elf() const-fn hand-roll.
//
// v1 init responsibilities (per `29§5`):
//   - print "oxide init: hello\n" via sys_write
//   - exit(0) via sys_exit
//
// Once busybox-sh integration lands, this becomes
// `execve("/bin/busybox", argv=["sh"], envp=[])`.

#include <sys/syscall.h>
#include <unistd.h>

static long
oxide_syscall3(long nr, long a0, long a1, long a2) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(nr), "D"(a0), "S"(a1), "d"(a2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

void _start(void) {
    static const char msg[] = "oxide init: hello from real-musl PID 1\n";
    oxide_syscall3(SYS_write, 1, (long)msg, sizeof(msg) - 1);
    oxide_syscall3(SYS_exit, 0, 0, 0);
    __builtin_unreachable();
}
