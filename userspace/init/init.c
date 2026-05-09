// PID 1: real-musl static-PIE init. Arch-portable: uses musl libc
// wrappers (write/execve/fork/wait/_exit) so the same source builds
// on x86_64 and aarch64.
//
// Built via `<arch>-linux-musl-gcc -static-pie -fPIE -O2 -nostartfiles`.
//
// Boot chain:
//   1. Print "oxide init: hello\n".
//   2. If /etc/oxide-init-smokes exists → run kernel-IPC + dual-image
//      acceptance smokes (sem/msg/mq/ptrace/mprotect/hello_dyn/
//      oxide-echo). Each prints its own PASS/FAIL marker.
//   3. Drop into /bin/sh respawn loop. With /dev/console fd 0/1/2
//      already wired by the kernel, busybox sh comes up interactive.

#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

static long mlen(const char* s) { long n = 0; while (s[n]) n++; return n; }

void _start(void) {
    static const char hello[] = "oxide init: hello from real-musl PID 1\n";
    write(1, hello, sizeof(hello) - 1);

    // Smokes gate: present file → run acceptance suite, absent →
    // skip straight to sh. xtask rootfs creates the marker by
    // default so existing CI keeps exercising the kernel-IPC path;
    // an interactive boot drops the marker before image build.
    int run_smokes = (access("/etc/oxide-init-smokes", F_OK) == 0);
    if (run_smokes) {
    // F62 exec-path bring-up smokes. /bin/bare = oxide_start.h
    // _start, no musl init. /bin/bare2 = same + reads argv[1].
    // /bin/bare3 = full musl crt1 (the same path busybox follows).
    // All three pass; busybox itself still mis-dispatches —
    // tracked separately, see state.md F62 notes.
    {
        long pid = (long)fork();
        if (pid == 0) {
            static char* argv0[] = { "bare", 0 };
            static char* envp[] = { 0 };
            execve("/bin/bare", argv0, envp);
            _exit(127);
        }
        int status; waitpid((int)pid, &status, 0);
    }
    {
        long pid = (long)fork();
        if (pid == 0) {
            static char* argv0[] = { "bare3", 0 };
            static char* envp[] = { 0 };
            execve("/bin/bare3", argv0, envp);
            _exit(127);
        }
        int status; waitpid((int)pid, &status, 0);
    }

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
            // /bin/echo is a busybox hardlink. The vendored busybox
            // is rebuilt with FEATURE_INSTALLER off so the --list/
            // --install code path is absent (per F147).
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
        "/bin/ptrace_singlestep_smoke",
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

    // F61 stage 0 — invoke /bin/oxide-echo (our static-musl tool,
    // NOT busybox). Isolates kernel exec/argv from any busybox
    // applet-routing concerns. Expected: "v1-oxide-echo: hello\n".
    {
        long pid = (long)fork();
        if (pid == 0) {
            static char* argv[] = { "oxide-echo", "hello", 0 };
            static char* envp[] = { 0 };
            static const char tag[] = "v1-oxide-echo: ";
            write(1, tag, sizeof(tag) - 1);
            execve("/bin/oxide-echo", argv, envp);
            static const char fail[] = "init: exec /bin/oxide-echo failed\n";
            write(1, fail, sizeof(fail) - 1);
            _exit(127);
        }
        int status;
        waitpid((int)pid, &status, 0);
    }

    } // end if (run_smokes)

    // Interactive sh loop. /dev/console fd 0/1/2 is wired by the
    // kernel before user-blob spawn (see dev_console.rs init_console_
    // fd_table); busybox sh comes up with a working stdin and prints
    // its prompt. Cap at 8 iters to avoid runaway when sh refuses to
    // start.
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
