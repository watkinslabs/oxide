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

    // svcd handoff was here but is disabled — staged at /bin/oxide-svcd
    // not /sbin/svcd, so the execve was guaranteed to fail with ENOENT,
    // and musl's errno write-on-failure path faults under FS_BASE=0
    // (oxide_start.h skips musl's TLS init). Re-enable when either
    // svcd works as PID 2 OR the FS_BASE / TLS-stub init is added.

    // Kernel-parity smoke: prove fork+execve+writev+wait4 round-trip
    // on the kernel's syscall surface from a real-musl PID 1 by
    // forking busybox-echo and waiting for its exit. Output:
    //   "init-fork-exec works"
    // is the success marker — if it appears the kernel-side
    // primitives are sound. We deliberately don't chain larger
    // applets here (their own argv parsing / TTY checks aren't
    // kernel concerns); the v1 acceptance binaries get separate
    // smoke harnesses.
    {
        long pid = (long)fork();
        if (pid == 0) {
            static char* argv0[] = { "echo", "init-fork-exec works", 0 };
            static char* envp[] = { 0 };
            execve("/bin/echo", argv0, envp);
            _exit(127);
        }
        int status;
        waitpid((int)pid, &status, 0);
    }

    // IPC smokes: drive each kernel-side blocking primitive end-to-
    // end from a real userspace program. Each child prints its own
    // "X_smoke: PASS\n" or "X_smoke: FAIL\n" to fd 1 and exits with
    // status 0/1; init reaps and ignores the status (the printed
    // marker is the actual gate).
    static const char* const smokes[] = {
        "/bin/sem_smoke",
        "/bin/msg_smoke",
        "/bin/mq_smoke",
        "/bin/ptrace_smoke",
        // F52: ptrace_singlestep_smoke is staged but not run from
        // boot — needs default-action SIGTRAP termination wired in
        // the kernel signal subsystem (currently sigpending bits get
        // set but no auto-terminate). Pulling forward when that
        // lands. Source is at /bin/ptrace_singlestep_smoke for
        // ad-hoc invocation.
        "/bin/mprotect_smoke",
        0,
    };
    for (int i = 0; smokes[i]; i++) {
        long pid = (long)fork();
        if (pid == 0) {
            char* argv0[] = { (char*)smokes[i], 0 };
            static char* envp[] = { 0 };
            execve(smokes[i], argv0, envp);
            _exit(127);
        }
        int status;
        waitpid((int)pid, &status, 0);
    }

    // PT_INTERP dual-image smoke: fork+exec /bin/hello_dyn (a -pie
    // binary linked against /lib/ld-musl-<arch>.so.1). Kernel ELF
    // loader sees PT_INTERP, dual-loads our stub linker, lands at
    // ld-musl entry, ld-musl falls through to hello_dyn's _start
    // which prints "hello-from-dyn". Marker is the gate.
    {
        long pid = (long)fork();
        if (pid == 0) {
            static char* argv0[] = { "hello_dyn", 0 };
            static char* envp[] = { 0 };
            execve("/bin/hello_dyn", argv0, envp);
            _exit(127);
        }
        int status;
        waitpid((int)pid, &status, 0);
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
