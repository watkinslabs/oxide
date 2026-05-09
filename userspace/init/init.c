// PID 1: real-musl static-pie init. Linked with the real musl
// crt1 (Scrt1.o + libc.a) — same startup path as busybox: musl's
// _start_c walks auxv, runs __init_libc + __init_tls (allocates
// the TCB, installs FS_BASE/TPIDR_EL0 via arch_prctl /
// PR_SET_TLS), then calls main().
//
// Build flags (xtask): `<arch>-linux-musl-gcc -static-pie -fPIE -O2`.
// No `-nostartfiles`, no shim — the kernel's auxv (`exec_stack.rs`)
// carries AT_PHDR/PHENT/PHNUM/PAGESZ/ENTRY/RANDOM/PLATFORM/EXECFN
// so musl's static-pie crt1 finds its phdrs and seeds the RNG
// without help.
//
// Boot chain:
//   1. Print "oxide init: hello\n".
//   2. If /etc/oxide-init-smokes exists → run kernel-IPC + dual-image
//      acceptance smokes. Each prints its own PASS/FAIL marker.
//   3. Drop into interactive sh respawn loop on /dev/console.
//      Today targets /bin/oxide-sh (the in-tree minimal shell);
//      switching to /bin/sh (busybox-ash) is gated on F151 — busybox
//      currently exits silently on interactive startup against this
//      kernel and needs a separate diagnosis.

#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

int main(int argc, char** argv, char** envp_in) {
    (void)argc; (void)argv; (void)envp_in;

    static const char hello[] = "oxide init: hello from real-musl PID 1\n";
    write(1, hello, sizeof(hello) - 1);

    // Smokes gate: present file → run acceptance suite, absent →
    // skip straight to sh. xtask rootfs creates the marker by
    // default so existing CI keeps exercising the kernel-IPC path;
    // an interactive boot drops the marker before image build.
    int marker_fd = open("/etc/oxide-init-smokes", O_RDONLY);
    int run_smokes = (marker_fd >= 0);
    if (marker_fd >= 0) close(marker_fd);
    if (run_smokes) {
        static const char m1[] = "init: smokes marker FOUND\n";
        write(1, m1, sizeof(m1) - 1);
    } else {
        static const char m1[] = "init: smokes marker MISSING -> interactive\n";
        write(1, m1, sizeof(m1) - 1);
    }

    if (run_smokes) {
    // F62 exec-path bring-up smoke (real-musl-crt1 isolation case).
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

    // Kernel-parity smoke: prove fork+execve+writev+wait4 round-trip
    // by forking busybox-echo. Output "init-fork-exec works" is the
    // success marker.
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
    // "X_smoke: PASS\n" or "X_smoke: FAIL\n" to fd 1.
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

    // PT_INTERP dual-image smoke: fork+exec /bin/hello_dyn.
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

    } // end if (run_smokes)

    // Interactive shell respawn loop. /dev/console fd 0/1/2 is wired
    // by the kernel before user-blob spawn (see dev_console.rs
    // init_console_fd_table). Targets /bin/sh (busybox-ash) — every
    // applet is reachable through this one binary. Cap at 8 iters
    // to prevent runaway when sh refuses to start.
    for (int i = 0; i < 8; i++) {
        long pid = (long)fork();
        if (pid == 0) {
            static char* argv[] = { "sh", 0 };
            static char* envp[] = { "PATH=/bin:/sbin", "HOME=/", "TERM=linux", 0 };
            execve("/bin/sh", argv, envp);
            static const char fail[] = "init: exec /bin/sh failed\n";
            write(1, fail, sizeof(fail) - 1);
            _exit(1);
        }
        int status;
        waitpid((int)pid, &status, 0);
    }
    return 0;
}
