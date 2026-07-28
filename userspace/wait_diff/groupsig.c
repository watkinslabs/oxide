/* A PROCESS-directed signal must be taken by whichever thread can take it.
 *
 * Linux keeps two pending sets per process: the thread-private
 * `task->pending` and the process-wide `signal->shared_pending`.
 * `kill(2)`/`sigqueue(3)` post to the shared set (`PIDTYPE_TGID`), and
 * `complete_signal` (`kernel/signal.c:963`) then walks the group for a thread
 * that `wants_signal()` — i.e. one that does NOT have the signal blocked —
 * and wakes THAT thread, remembering it in `signal->curr_target`. Dequeue is
 * symmetric: `dequeue_signal` tries `&tsk->pending` first and then
 * `&tsk->signal->shared_pending` (`kernel/signal.c`), so any thread reaching a
 * delivery point with the signal unblocked can consume it.
 *
 * The consequence this file asserts: a process whose MAIN thread blocks
 * SIGTERM still dies of `kill(pid, SIGTERM)` as long as some other thread has
 * it unblocked. That is not a corner case — it is how every glib/GIO program
 * is built (the main thread blocks the termination signals and a worker owns
 * them), and it is what systemd relies on to stop a service.
 *
 * A kernel that posts a process-directed signal onto the group LEADER only,
 * and lets only the leader dequeue it, produces `outcome=blocked` here while
 * every thread-directed case in `abortsig.c` stays green — the two cases
 * cannot substitute for each other.
 */
#include "probe.h"

#include <stddef.h>

struct group_shared {
    volatile sig_atomic_t ready;   /* sibling up with the signal unblocked */
    volatile sig_atomic_t handled; /* the handler ran, and in which thread */
    volatile sig_atomic_t in_main; /* handler ran on the main thread */
    volatile sig_atomic_t stop;    /* release for the sibling's loop */
    volatile sig_atomic_t main_blocked;  /* main thread still has the signal blocked */
    volatile sig_atomic_t sib_blocked;   /* sibling does not */
    volatile sig_atomic_t main_tid;      /* gettid() of the main thread */
    volatile sig_atomic_t handler_tid;   /* gettid() inside the handler */
    volatile sig_atomic_t tls_agrees;    /* pthread_self() told the same story */
};

#define GRP_READY_MS   2000u
#define GRP_GUARD_MS  10000u
#define GRP_SLEEP_MS     20u
#define GRP_SETUP_FAIL   70

static struct group_shared *g_gsh;
static pthread_t g_main_thread;

static struct group_shared *gshared_new(void) {
    void *p = mmap(NULL, sizeof(struct group_shared), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    memset(p, 0, sizeof(struct group_shared));
    return (struct group_shared *)p;
}

static int gwait_ready(struct group_shared *sh, unsigned ms) {
    long long deadline = mono_ms() + (long long)ms;
    while (!sh->ready) {
        if (mono_ms() >= deadline) return 0;
        sleep_ms(5);
    }
    return 1;
}

static const char *gsig_name(int sig) {
    switch (sig) {
    case SIGTERM: return "term";
    case SIGUSR1: return "usr1";
    case SIGKILL: return "kill";
    case SIGABRT: return "abrt";
    case SIGSEGV: return "segv";
    default:      return "other";
    }
}

/* Block `sig` on the CALLING thread only. Linux's signal mask is per-thread
 * even though the disposition is per-process — that asymmetry is the whole
 * subject of this file. */
static int block_here(int sig) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, sig);
    return pthread_sigmask(SIG_BLOCK, &s, NULL);
}

/* `pthread_create` hands the new thread the CREATING thread's mask, so a
 * sibling started after the main thread blocked the signal inherits the block
 * and no thread can take it. Real glib/GIO code unblocks in the worker for
 * exactly this reason; the probe must too, or the row reports a userspace
 * mistake as a kernel defect (real Linux answered `blocked` until this was
 * fixed). */
static int unblock_here(int sig) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, sig);
    return pthread_sigmask(SIG_UNBLOCK, &s, NULL);
}

/* ------------------------------- 1: fatal signal, only a sibling can take it */

static void *term_sibling(void *arg) {
    struct group_shared *sh = (struct group_shared *)arg;
    if (unblock_here(SIGTERM) != 0) return NULL;
    sh->ready = 1;
    while (!sh->stop) sleep_ms(GRP_SLEEP_MS);
    return NULL;
}

/* The main thread blocks SIGTERM; the sibling does not. `kill(pid, SIGTERM)`
 * must still terminate the process, because `complete_signal` picks the
 * sibling. A kernel that only ever posts to (and dequeues from) the leader
 * leaves the signal pending-but-blocked forever. */
static void term_child(struct group_shared *sh) {
    pthread_t th;
    if (block_here(SIGTERM) != 0) _exit(GRP_SETUP_FAIL);
    if (pthread_create(&th, NULL, term_sibling, sh) != 0) _exit(GRP_SETUP_FAIL);
    for (;;) sleep_ms(GRP_SLEEP_MS);
}

static void term_case(void) {
    struct group_shared *sh = gshared_new();
    if (sh == NULL) { out("groupsig", "term_taken_by_unblocked_thread", "outcome=setup_failed|sig=none"); return; }
    pid_t pid = fork();
    if (pid == 0) { term_child(sh); _exit(GRP_SETUP_FAIL); }
    if (pid < 0) {
        out("groupsig", "term_taken_by_unblocked_thread", "outcome=fork_failed|sig=none");
        return;
    }
    if (gwait_ready(sh, GRP_READY_MS)) {
        /* `grpnoterm`: nothing is ever sent, so the group survives on any
         * kernel — the defective record, manufactured in userspace. */
        if (!mutant("grpnoterm")) kill(pid, SIGTERM);
    }
    int st = 0;
    int reaped = wait_bounded(pid, GRP_GUARD_MS, &st);
    if (!reaped) { kill(pid, SIGKILL); wait_bounded(pid, GRP_GUARD_MS, &st); }
    const char *outcome = "blocked", *sig = "none";
    if (reaped) {
        if (WIFSIGNALED(st)) { outcome = "signalled"; sig = gsig_name(WTERMSIG(st)); }
        else if (WIFEXITED(st)) outcome = WEXITSTATUS(st) == GRP_SETUP_FAIL ? "setup_failed" : "exited";
    }
    out("groupsig", "term_taken_by_unblocked_thread", "outcome=%s|sig=%s", outcome, sig);
    munmap((void *)sh, sizeof *sh);
}

/* ---------------------- 2: caught signal, only a sibling has it unblocked */

/* Disposition is per-PROCESS (`sighand_struct` is shared), so the handler the
 * main thread installs is the one the sibling runs. `in_main=0` is the claim:
 * the signal was delivered to the thread that could take it, not to the one it
 * was posted against. */
/* Which thread ran is decided by `gettid()`, not by `pthread_self()`: the
 * pthread identity comes out of the thread pointer, so a kernel that entered
 * the handler with the wrong TLS register would make a CORRECT delivery look
 * like a delivery to the main thread. `tls_agrees` records whether the two
 * views match, so the row can tell a delivery defect from a TLS defect instead
 * of blaming whichever is guessed first. */
static void usr1_handler(int sig) {
    (void)sig;
    if (g_gsh == NULL) return;
    pid_t me = (pid_t)syscall(SYS_gettid);
    int by_tid = (me == (pid_t)g_gsh->main_tid) ? 1 : 0;
    int by_tls = pthread_equal(pthread_self(), g_main_thread) ? 1 : 0;
    g_gsh->handler_tid = me;
    g_gsh->in_main = by_tid;
    g_gsh->tls_agrees = (by_tid == by_tls) ? 1 : 0;
    g_gsh->handled = 1;
    g_gsh->stop = 1;
}

static void *usr1_sibling(void *arg) {
    struct group_shared *sh = (struct group_shared *)arg;
    if (unblock_here(SIGUSR1) != 0) return NULL;
    sigset_t cur;
    sigemptyset(&cur);
    if (pthread_sigmask(SIG_BLOCK, NULL, &cur) == 0)
        sh->sib_blocked = sigismember(&cur, SIGUSR1) ? 1 : 0;
    sh->ready = 1;
    while (!sh->stop) sleep_ms(GRP_SLEEP_MS);
    return NULL;
}

static void usr1_child(struct group_shared *sh) {
    struct sigaction sa;
    pthread_t th;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = usr1_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) _exit(GRP_SETUP_FAIL);
    g_main_thread = pthread_self();
    sh->main_tid = (sig_atomic_t)syscall(SYS_gettid);
    if (block_here(SIGUSR1) != 0) _exit(GRP_SETUP_FAIL);
    if (pthread_create(&th, NULL, usr1_sibling, sh) != 0) _exit(GRP_SETUP_FAIL);
    /* Re-read the masks the kernel actually holds, so a mismatch says WHICH
     * half broke: `main_blocked=0` means the block never took effect (a
     * `rt_sigprocmask` / thread-mask defect), while `main_blocked=1` with
     * `in_main=1` means the kernel delivered a signal to a thread that has it
     * blocked (a delivery defect). Without this the row can only report that
     * something is wrong. */
    sigset_t cur;
    sigemptyset(&cur);
    if (pthread_sigmask(SIG_BLOCK, NULL, &cur) == 0)
        sh->main_blocked = sigismember(&cur, SIGUSR1) ? 1 : 0;
    pthread_join(th, NULL);
    _exit(0);
}

static void usr1_case(void) {
    struct group_shared *sh = gshared_new();
    if (sh == NULL) { out("groupsig", "handler_runs_in_unblocked_thread", "outcome=setup_failed|handled=0|in_main=0|tls_agrees=0|main_blocked=0|sib_blocked=0"); return; }
    pid_t pid = fork();
    if (pid == 0) { g_gsh = sh; usr1_child(sh); _exit(GRP_SETUP_FAIL); }
    if (pid < 0) {
        out("groupsig", "handler_runs_in_unblocked_thread", "outcome=fork_failed|handled=0|in_main=0|tls_agrees=0|main_blocked=0|sib_blocked=0");
        return;
    }
    if (gwait_ready(sh, GRP_READY_MS)) {
        /* `grpnousr1`: no signal is sent, so nothing can be handled. */
        if (!mutant("grpnousr1")) kill(pid, SIGUSR1);
    }
    int st = 0;
    int reaped = wait_bounded(pid, GRP_GUARD_MS, &st);
    if (!reaped) { kill(pid, SIGKILL); wait_bounded(pid, GRP_GUARD_MS, &st); }
    const char *outcome = "blocked";
    if (reaped) {
        if (WIFSIGNALED(st)) outcome = "signalled";
        else if (WIFEXITED(st)) outcome = WEXITSTATUS(st) == GRP_SETUP_FAIL ? "setup_failed" : "exited";
    }
    out("groupsig", "handler_runs_in_unblocked_thread",
        "outcome=%s|handled=%d|in_main=%d|tls_agrees=%d|main_blocked=%d|sib_blocked=%d",
        outcome, sh->handled ? 1 : 0, sh->in_main ? 1 : 0, sh->tls_agrees ? 1 : 0,
        sh->main_blocked ? 1 : 0, sh->sib_blocked ? 1 : 0);
    munmap((void *)sh, sizeof *sh);
}

void probe_groupsig(void) {
    term_case();
    usr1_case();
}
