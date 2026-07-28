/* A fatal signal raised BY a thread must kill the whole thread group.
 *
 * glibc's `abort()` is the real-world consumer, and its shape is what makes
 * the defect visible rather than silent. Disassembled from the shipped
 * `libc.so.6` rather than recalled:
 *
 *     raise (SIGABRT);                      <- pthread_kill(self) -> tgkill
 *     __abort_lock_wrlock (0);
 *     memset (&sa, 0, sizeof sa);           <- sa_handler = SIG_DFL
 *     sigfillset (&sa.sa_mask);
 *     __libc_sigaction (SIGABRT, &sa, NULL);
 *     __pthread_raise_internal (SIGABRT);   <- tgkill(getpid(), gettid(), 6)
 *     rt_sigprocmask (SIG_UNBLOCK, {SIGABRT}, NULL, 8);
 *     ABORT_INSTRUCTION;                    <- x86 `hlt` -> #GP -> SIGSEGV
 *     _exit (127);
 *
 * The second raise is unconditionally against SIG_DFL, so on Linux control
 * never reaches `ABORT_INSTRUCTION`. A process that dies `11/SEGV` out of
 * `abort()` is reporting a kernel that let BOTH `tgkill`s return — which is
 * exactly how gdm died (`scratch/linux-compliance-findings.md` §10 item 3).
 * `sig=` is therefore the discriminator on the abort rows: `abrt` is a working
 * kernel, anything else is the fall-through.
 *
 * Linux, read in `/home/nd/oxide/linux-master` rather than assumed: SIGABRT is
 * in `SIG_KERNEL_COREDUMP_MASK` (`include/linux/signal.h:428`), so
 * `complete_signal` (`kernel/signal.c:1003`) does NOT take its
 * `SIGNAL_GROUP_EXIT` fast path — that arm is guarded by
 * `!sig_kernel_coredump(sig)`. The kill happens one step later, in
 * `get_signal`'s `fatal:` arm: `vfs_coredump()` then `do_group_exit(signr)`
 * (`kernel/exit.c:1127`), which latches `group_exit_code`, runs
 * `zap_other_threads` and takes every sibling down. `wait_task_zombie` reports
 * `signal->group_exit_code`, so the parent sees SIGABRT even when the thread
 * that aborted was not the group leader.
 *
 * Determinism: the core-dump bit of the wait status is NOT printed. Whether a
 * dump happened depends on `kernel.core_pattern`, RLIMIT_CORE and the
 * dumpability flag, none of which is the semantics under test and all of which
 * legitimately differ between this machine and the guest.
 */
#include "probe.h"

#include <stddef.h>
#include <sys/resource.h>

/* Shared across the fork so an observation made by a process that is about to
 * be killed still reaches the printer. */
struct abort_shared {
    volatile sig_atomic_t returned; /* a raise/abort call came back */
    volatile sig_atomic_t handled;  /* the installed SIGABRT handler ran */
    volatile sig_atomic_t err;      /* errno `raise` came back with, if it did */
};

/* Ten times the sibling-startup cost, the same margin every other case in this
 * probe uses, so guest slowness can never reach the verdict. */
#define ABORT_GUARD_MS 10000u
/* Siblings park in short sleeps rather than spinning: a fatal signal must
 * reach a thread blocked in a syscall as well as one on-CPU, and the sleep
 * keeps the guest cheap. `spinsig` already owns the pure-userspace-spin case. */
#define ABORT_SIB_SLEEP_MS 20u

/* Exit code used when a group survives its own abort. Never produced by a
 * correct kernel. */
#define ABORT_SURVIVED   71
#define ABORT_SETUP_FAIL 70

static struct abort_shared *g_sh;

static struct abort_shared *shared_new(void) {
    void *p = mmap(NULL, sizeof(struct abort_shared), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    memset(p, 0, sizeof(struct abort_shared));
    return (struct abort_shared *)p;
}

static void shared_free(struct abort_shared *sh) {
    munmap((void *)sh, sizeof(struct abort_shared));
}

static void *sib_thread(void *arg) {
    struct abort_shared *sh = (struct abort_shared *)arg;
    while (!sh->returned) sleep_ms(ABORT_SIB_SLEEP_MS);
    return NULL;
}

/* `n` siblings, so "the group leader happened to be the thread that died"
 * cannot pass for a working group exit. Returns 0 on failure. */
static int start_siblings(struct abort_shared *sh, pthread_t *t, int n) {
    for (int i = 0; i < n; i++)
        if (pthread_create(&t[i], NULL, sib_thread, sh) != 0) return 0;
    return 1;
}

/* Keep either kernel from writing a core per case. Linux gates the dump on
 * RLIMIT_CORE (`fs/coredump.c`); no case here inspects a dump. */
static void no_core(void) {
    struct rlimit rl = { 0, 0 };
    setrlimit(RLIMIT_CORE, &rl);
}

static void abort_handler(int sig) {
    (void)sig;
    if (g_sh != NULL) g_sh->handled = 1;
}

/* `abrtnokill` — the mutant that manufactures the defective kernel's record in
 * userspace. A SIGABRT handler that merely returns keeps both raises from
 * killing anything, so the caller comes back and the child exits normally.
 * Without it a green row here would prove nothing: every row would be equally
 * green for a probe that never raised at all. */
static void fatal_call(void) {
    if (mutant("abrtnokill")) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = abort_handler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGABRT, &sa, NULL);
        raise(SIGABRT);
        raise(SIGABRT);
        g_sh->returned = 1;
        _exit(ABORT_SURVIVED);
    }
    abort();
}

static const char *sig_name(int sig) {
    switch (sig) {
    case SIGABRT: return "abrt";
    case SIGSEGV: return "segv";
    case SIGKILL: return "kill";
    case SIGILL:  return "ill";
    case SIGTRAP: return "trap";
    case SIGBUS:  return "bus";
    default:      return "other";
    }
}

/* What the wait status says about a group that was required to die. `blocked`
 * is the group that neither died nor exited inside the guard — the shape a
 * kernel that loses the signal entirely produces. */
static void outcome_of(int reaped, int st, const char **outcome, const char **sig) {
    *outcome = "blocked";
    *sig = "none";
    if (!reaped) return;
    if (WIFSIGNALED(st)) { *outcome = "signalled"; *sig = sig_name(WTERMSIG(st)); return; }
    if (WIFEXITED(st)) {
        *outcome = WEXITSTATUS(st) == ABORT_SETUP_FAIL ? "setup_failed" : "exited";
        return;
    }
    *outcome = "other";
}

/* Extra observables a row carries beyond outcome/sig. */
#define AB_HANDLED  1
#define AB_RETURNED 2

/* Run `child` in a fresh process and print how it died. If the guard expires
 * the probe tears the group down itself, so one defect cannot swallow the
 * cases behind it (`wait_bounded`'s contract). */
static void run_case(const char *test, void (*child)(struct abort_shared *), int extras) {
    struct abort_shared *sh = shared_new();
    if (sh == NULL) { out("abortsig", test, "outcome=setup_failed|sig=none"); return; }
    pid_t pid = fork();
    if (pid == 0) { g_sh = sh; no_core(); child(sh); _exit(ABORT_SURVIVED); }
    if (pid < 0) {
        out("abortsig", test, "outcome=fork_failed|sig=none");
        shared_free(sh);
        return;
    }
    int st = 0;
    int reaped = wait_bounded(pid, ABORT_GUARD_MS, &st);
    if (!reaped) {
        kill(pid, SIGKILL);
        wait_bounded(pid, ABORT_GUARD_MS, &st);
    }
    const char *outcome, *sig;
    outcome_of(reaped, st, &outcome, &sig);
    if (extras & AB_RETURNED)
        out("abortsig", test, "outcome=%s|sig=%s|returned=%d|raise_err=%s",
            outcome, sig, sh->returned ? 1 : 0,
            sh->returned ? errno_name(sh->err) : "none");
    else if (extras & AB_HANDLED)
        out("abortsig", test, "outcome=%s|sig=%s|handled=%d", outcome, sig, sh->handled ? 1 : 0);
    else
        out("abortsig", test, "outcome=%s|sig=%s", outcome, sig);
    shared_free(sh);
}

/* ------------------------------------------------------ 1: single-threaded */

static void c_single(struct abort_shared *sh) {
    (void)sh;
    fatal_call();
}

/* ------------------------------------------------- 2: the group leader aborts */

static void c_leader(struct abort_shared *sh) {
    pthread_t t[2];
    if (!start_siblings(sh, t, 2)) _exit(ABORT_SETUP_FAIL);
    fatal_call();
}

/* -------------------------------------------- 3: a NON-leader thread aborts */

static void *abort_thread(void *arg) {
    (void)arg;
    fatal_call();
    return NULL;
}

/* The case gdm hit. The parent must still reap SIGABRT and not SIGKILL:
 * Linux's `do_group_exit` latches `group_exit_code` BEFORE zapping, so the
 * leader — felled by the zap's own SIGKILL — reports the aborting thread's
 * signal (`kernel/exit.c:1131`, and `wait_task_zombie`'s
 * `SIGNAL_GROUP_EXIT` arm at `kernel/exit.c:1218`). */
static void c_sibling(struct abort_shared *sh) {
    pthread_t t[1], ab;
    if (!start_siblings(sh, t, 1)) _exit(ABORT_SETUP_FAIL);
    if (pthread_create(&ab, NULL, abort_thread, NULL) != 0) _exit(ABORT_SETUP_FAIL);
    for (;;) sleep_ms(ABORT_SIB_SLEEP_MS);
}

/* ----------------------------- 4: bare raise(SIGABRT), no libc scaffolding */

/* `abort()` gets three chances to kill (two raises and the abort instruction);
 * a single `raise` against SIG_DFL gets one, so these are the rows that assert
 * the FIRST `tgkill` is fatal. `returned=1` is direct evidence that the
 * raising thread executed another instruction, which a correct kernel makes
 * unreachable, and `raise_err=` then names WHY — a `tgkill` that reported
 * ESRCH/EPERM never posted anything, which is a different defect from one that
 * posted a signal nobody delivered. `raise_err=none` whenever nothing
 * returned, so the correct-kernel record carries no host-specific value. */
static void do_raise(struct abort_shared *sh) {
    /* `abrtnoraise`: nothing is ever raised, so the group survives on any
     * kernel — the defective record, manufactured in userspace. */
    if (!mutant("abrtnoraise")) {
        errno = 0;
        raise(SIGABRT);
    }
    sh->err = errno;
    sh->returned = 1;
}

static void *raise_thread(void *arg) {
    do_raise((struct abort_shared *)arg);
    return NULL;
}

/* Leader raises. Separates "this kernel cannot make `tgkill` fatal at all"
 * from "it cannot do so for a thread that is not the group leader" — the two
 * have different fixes, and a single row cannot tell them apart. */
static void c_raise_leader(struct abort_shared *sh) {
    pthread_t t[2];
    if (!start_siblings(sh, t, 2)) _exit(ABORT_SETUP_FAIL);
    do_raise(sh);
    for (;;) sleep_ms(ABORT_SIB_SLEEP_MS);
}

static void c_raise_sibling(struct abort_shared *sh) {
    pthread_t t[1], rz;
    if (!start_siblings(sh, t, 1)) _exit(ABORT_SETUP_FAIL);
    if (pthread_create(&rz, NULL, raise_thread, sh) != 0) _exit(ABORT_SETUP_FAIL);
    for (;;) sleep_ms(ABORT_SIB_SLEEP_MS);
}

/* ------------------------------- 5: a SIGABRT handler must not save anyone */

/* glibc resets the disposition to SIG_DFL between its two raises, so a handler
 * that returns delays the death by exactly one raise. `handled=1` proves the
 * handler really ran, which is what separates this row from case 2. */
static void c_handler(struct abort_shared *sh) {
    struct sigaction sa;
    pthread_t t[2];
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = abort_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGABRT, &sa, NULL) != 0) _exit(ABORT_SETUP_FAIL);
    if (!start_siblings(sh, t, 2)) _exit(ABORT_SETUP_FAIL);
    fatal_call();
}

/* ----------------------------------- 6: a blocked SIGABRT must not save one */

/* glibc unblocks SIGABRT only AFTER both raises (see the header disassembly),
 * so this row exercises delivery on the way out of `rt_sigprocmask` itself:
 * the signal stays pending-but-blocked across both raises and becomes
 * deliverable at the unblock's return to user mode. */
static void c_blocked(struct abort_shared *sh) {
    sigset_t s;
    pthread_t t[2];
    sigemptyset(&s);
    sigaddset(&s, SIGABRT);
    if (pthread_sigmask(SIG_BLOCK, &s, NULL) != 0) _exit(ABORT_SETUP_FAIL);
    if (!start_siblings(sh, t, 2)) _exit(ABORT_SETUP_FAIL);
    fatal_call();
}

void probe_abortsig(void) {
    run_case("single_abort",       c_single,        0);
    run_case("leader_abort",       c_leader,        0);
    run_case("sibling_abort",      c_sibling,       0);
    run_case("leader_raise_dfl",   c_raise_leader,  AB_RETURNED);
    run_case("sibling_raise_dfl",  c_raise_sibling, AB_RETURNED);
    run_case("handler_then_abort", c_handler,       AB_HANDLED);
    run_case("blocked_then_abort", c_blocked,       0);
}
