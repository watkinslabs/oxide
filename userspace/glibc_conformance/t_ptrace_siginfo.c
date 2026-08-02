/* A tracer stopped on its tracee's SIGSEGV must be able to read WHY.
 *
 * `PTRACE_GETSIGINFO` is how every debugger learns that: si_code says which
 * `_sifields` union arm is valid, and for a fault that arm carries si_addr —
 * the address the tracee actually dereferenced. Reporting the stop as
 * `SI_USER` with a pid in those bytes is indistinguishable from a `kill(2)`,
 * so gdb cannot tell a wild pointer from a signal someone sent.
 *
 * The tracee faults on a KNOWN address, so si_addr is checkable rather than
 * merely non-zero. Output is arch-neutral booleans: the host oracle and either
 * guest arch produce the same frame.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* The address the tracee dereferences. Page-aligned, never mapped, and far
 * enough from 0 that it cannot be confused with a zeroed field or with any
 * plausible pid. */
#define FAULT_ADDR 0x00000000deadb000UL

/* Read through a volatile so the compiler cannot fold the store away or
 * replace the fault with a trap of its own choosing. */
static int *volatile fault_target;

int main(void)
{
    int stopped_on_segv = 0, code_is_fault = 0, addr_matches = 0;
    int addr_is_not_a_pid = 0, signo_is_segv = 0;
    siginfo_t si;
    pid_t pid;
    int st;

    fault_target = (int *)FAULT_ADDR;
    fflush(NULL);
    pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(3);
        raise(SIGSTOP);
        *fault_target = 1;
        _exit(4);
    }

    /* The child's own SIGSTOP: it is now traced and stopped. */
    if (waitpid(pid, &st, 0) != pid || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) {
        fprintf(stderr, "no initial stop\n");
        kill(pid, SIGKILL);
        return 1;
    }
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) { perror("cont"); kill(pid, SIGKILL); return 1; }

    /* The signal-delivery stop for the fault — the stop a debugger reports a
     * crash from. */
    if (waitpid(pid, &st, 0) != pid || !WIFSTOPPED(st)) {
        fprintf(stderr, "no fault stop\n");
        kill(pid, SIGKILL);
        return 1;
    }
    stopped_on_segv = (WSTOPSIG(st) == SIGSEGV);

    memset(&si, 0, sizeof(si));
    if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &si) != 0) {
        perror("getsiginfo");
        kill(pid, SIGKILL);
        return 1;
    }

    signo_is_segv = (si.si_signo == SIGSEGV);
    /* SEGV_MAPERR / SEGV_ACCERR are the two a page fault raises. SI_USER (0)
     * or SI_KERNEL (0x80) here means the record was built as a kill. */
    code_is_fault = (si.si_code == SEGV_MAPERR || si.si_code == SEGV_ACCERR);
    addr_matches = ((uintptr_t)si.si_addr == FAULT_ADDR);
    /* The precise defect: the tracer's own pid written into the bytes the
     * `_sigfault` arm uses for si_addr. */
    addr_is_not_a_pid = ((uintptr_t)si.si_addr != (uintptr_t)getpid());

    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);

    printf("stopped_on_segv=%d\n", stopped_on_segv);
    printf("signo_is_segv=%d\n", signo_is_segv);
    printf("code_is_fault=%d\n", code_is_fault);
    printf("addr_matches_fault=%d\n", addr_matches);
    printf("addr_is_not_a_pid=%d\n", addr_is_not_a_pid);
    return 0;
}
