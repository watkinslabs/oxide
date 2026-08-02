/* A tracer attached to a LIVE process must see the program counter the
 * tracee is actually stopped at.
 *
 * The interesting stop is a fault, not a syscall: at a syscall stop the
 * x86-64 entry frame legitimately holds the user return address in `rcx` as
 * well as in `rip`, so a tracer reading the wrong slot still reports a
 * plausible value. A SIGSEGV stop has no such coincidence — a wrong slot
 * reports an unrelated register, and the redirect below then resumes the
 * tracee at an address it was never meant to run.
 *
 * Output is arch-neutral booleans so the host oracle and an aarch64 guest
 * produce the same frame.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/* Bytes of `crash_fn` the faulting store may sit at. Generous, but far
 * smaller than the distance between two distinct registers' values. */
#define FN_SPAN 256

/* Exit status the tracee reports once the tracer has moved its program
 * counter. Distinct from every status the untouched program can produce. */
#define REDIRECTED_STATUS 7

/* Read through a volatile so the compiler cannot prove the store is to a
 * null pointer and replace the fault with a trap of its own choosing. */
static int *volatile fault_target;

__attribute__((noinline)) static void crash_fn(void)
{
    *fault_target = 1;
}

__attribute__((noinline)) static void recover_fn(void)
{
    _exit(REDIRECTED_STATUS);
}

static unsigned long long pc_of(const struct user_regs_struct *r)
{
#if defined(__x86_64__)
    return r->rip;
#else
    return r->pc;
#endif
}

static void set_pc(struct user_regs_struct *r, unsigned long long pc)
{
#if defined(__x86_64__)
    r->rip = pc;
#else
    r->pc = pc;
#endif
}

static unsigned long long sp_of(const struct user_regs_struct *r)
{
#if defined(__x86_64__)
    return r->rsp;
#else
    return r->sp;
#endif
}

static int getregs(pid_t pid, struct user_regs_struct *r)
{
    struct iovec io = { .iov_base = r, .iov_len = sizeof(*r) };
    return ptrace(PTRACE_GETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &io);
}

static int setregs(pid_t pid, struct user_regs_struct *r)
{
    struct iovec io = { .iov_base = r, .iov_len = sizeof(*r) };
    return ptrace(PTRACE_SETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &io);
}

int main(void)
{
    int stopped_on_segv = 0, pc_in_crash_fn = 0, sp_nonzero = 0, redirected = 0;
    pid_t pid;
    int st;

    fault_target = NULL;
    fflush(NULL);
    pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(3);
        raise(SIGSTOP);
        crash_fn();
        _exit(4);
    }

    /* The child's own SIGSTOP: it is now traced and stopped. */
    if (waitpid(pid, &st, 0) != pid || !WIFSTOPPED(st) || WSTOPSIG(st) != SIGSTOP) {
        fprintf(stderr, "no initial stop\n");
        kill(pid, SIGKILL);
        return 1;
    }
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) { perror("cont"); kill(pid, SIGKILL); return 1; }

    /* The fault. This is the stop a debugger attaching to a crashed or
     * running process sees, and the one that reads a real trap frame. */
    if (waitpid(pid, &st, 0) != pid || !WIFSTOPPED(st)) {
        fprintf(stderr, "no fault stop\n");
        kill(pid, SIGKILL);
        return 1;
    }
    stopped_on_segv = (WSTOPSIG(st) == SIGSEGV);

    struct user_regs_struct r;
    memset(&r, 0, sizeof(r));
    if (getregs(pid, &r) != 0) { perror("getregset"); kill(pid, SIGKILL); return 1; }

    unsigned long long pc = pc_of(&r);
    unsigned long long fn = (unsigned long long)(uintptr_t)crash_fn;
    pc_in_crash_fn = (pc >= fn && pc < fn + FN_SPAN);
    sp_nonzero = (sp_of(&r) != 0);

    /* Write side: move the tracee's program counter somewhere it would never
     * reach on its own and suppress the signal. A wrong slot resumes the
     * tracee at the faulting store again. */
    set_pc(&r, (unsigned long long)(uintptr_t)recover_fn);
    if (setregs(pid, &r) != 0) { perror("setregset"); kill(pid, SIGKILL); return 1; }
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) { perror("cont2"); kill(pid, SIGKILL); return 1; }
    if (waitpid(pid, &st, 0) == pid && WIFEXITED(st))
        redirected = (WEXITSTATUS(st) == REDIRECTED_STATUS);
    else
        kill(pid, SIGKILL);

    printf("stopped_on_segv=%d\n", stopped_on_segv);
    printf("pc_in_crash_fn=%d\n", pc_in_crash_fn);
    printf("sp_nonzero=%d\n", sp_nonzero);
    printf("setregs_redirected_pc=%d\n", redirected);
    return 0;
}
