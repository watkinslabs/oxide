// /bin/ptrace_singlestep_smoke — exercises PTRACE_SINGLESTEP +
// observes the resulting SIGTRAP.
//
// Test: parent forks; child runs a short syscall loop. Parent
// ATTACHes + issues PTRACE_SINGLESTEP. With F49+F50+F51 the
// kernel arms RFLAGS.TF / SPSR.SS on the child's next return-to-
// user, the next user instruction traps, the kernel posts SIGTRAP,
// and the child dies via signal. PASS iff WIFSIGNALED && WTERMSIG
// == SIGTRAP. If single-step is treated as plain CONT (pre-F50/51
// behaviour), the child runs to completion and _exit(99)s — FAIL.

/* F152-1: real musl crt1 — no shim */
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;

    pid_t pid = fork();
    if (pid < 0) {
        write(2, "ptrace_singlestep_smoke: fork fail\n", 35);
        return 1;
    }

    if (pid == 0) {
        // Child: bounded syscall loop so the kernel has a return-
        // to-user path to observe Task.singlestep on. If the loop
        // completes (single-step never fired) exit with sentinel 99.
        for (long i = 0; i < 50000; i++) {
            // 0-byte write — cheap syscall, gives the kernel a sysret
            // boundary every iteration so TF/SS arming is observable.
            write(2, "", 0);
        }
        _exit(99);
    }

    // Parent: arm single-step on the child and wait for a signal.
    ptrace(PTRACE_ATTACH, pid, 0, 0);
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);

    int status = 0;
    pid_t r = waitpid(pid, &status, 0);
    int passed = (r == pid)
              && WIFSIGNALED(status)
              && (WTERMSIG(status) == 5 /* SIGTRAP */);

    if (!passed) {
        // Best-effort cleanup if the child is still alive.
        ptrace(PTRACE_KILL, pid, 0, 0);
        waitpid(pid, 0, 0);
    }

    if (passed) {
        write(1, "ptrace_singlestep_smoke: PASS\n", 30);
        return 0;
    } else {
        write(1, "ptrace_singlestep_smoke: FAIL\n", 30);
        return 1;
    }
}
