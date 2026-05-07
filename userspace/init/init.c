// PID 1: real-musl static-PIE init. Arch-portable: uses musl libc
// wrappers (write/execve/fork/wait/_exit) so the same source builds
// on x86_64 and aarch64.
//
// Built via `<arch>-linux-musl-gcc -static-pie -fPIE -O2 -nostartfiles`.
//
// Boot chain:
//   1. Print "oxide init: hello\n".
//   2. Try execve("/sbin/svcd", argv=["svcd"], envp=[]) — if svcd
//      exists, hand off the supervision job.
//   3. Fallback: respawn /bin/sh in a loop (legacy P5 behavior),
//      capped at 8 iterations to avoid runaway when sh refuses
//      to start.

#include <unistd.h>
#include <sys/wait.h>

static long mlen(const char* s) { long n = 0; while (s[n]) n++; return n; }

void _start(void) {
    static const char hello[] = "oxide init: hello from real-musl PID 1\n";
    write(1, hello, sizeof(hello) - 1);

    // Try to hand off to svcd. If it isn't installed (or exec fails)
    // we fall through to the legacy shell-respawn loop.
    {
        static char* argv[] = { "svcd", 0 };
        static char* envp[] = { 0 };
        execve("/sbin/svcd", argv, envp);
        // If we get here, exec failed; carry on with the fallback.
        static const char no_svcd[] =
            "init: /sbin/svcd not present, falling back to shell respawn\n";
        write(1, no_svcd, sizeof(no_svcd) - 1);
    }

    for (int i = 0; i < 8; i++) {
        long pid = (long)fork();
        if (pid == 0) {
            static char* argv[] = { "sh", 0 };
            static char* envp[] = { 0 };
            execve("/bin/sh", argv, envp);
            static const char fail[] = "init: exec /bin/sh failed\n";
            write(1, fail, sizeof(fail) - 1);
            _exit(1);
        }
        int status;
        waitpid((int)pid, &status, 0);
    }
    _exit(0);
}
