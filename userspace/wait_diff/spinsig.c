/* Signal delivery to a task spinning in USERSPACE, with no syscall in the loop.
 *
 * Linux checks for pending work on EVERY return to user mode, not only at the
 * syscall tail: `exit_to_user_mode_prepare` -> `__exit_to_user_mode_loop`
 * (kernel/entry/common.c) runs `arch_do_signal_or_restart()` whenever
 * `_TIF_SIGPENDING` is set, and the IRQ and exception returns funnel through
 * the same helper (`irqentry_exit_to_user_mode`). So a task burning CPU in a
 * pure compute loop takes its signal at the next timer tick — SIGUSR1 from a
 * peer, its own `alarm(2)` SIGALRM, and SIGKILL alike.
 *
 * B1471 found oxide delivering ONLY at the syscall-return tail: a loop that
 * issues no syscall reaches no delivery point, so it takes no signal at all
 * and cannot even be killed. Nothing had ever watched that happen — every
 * other wait_diff case is parked in a syscall by construction, which is the
 * one shape the defective path handles.
 *
 * Bounding a case whose failure mode is "the task never takes a signal" needs
 * care: the usual `alarm()` guard is EXACTLY the mechanism under test, and
 * `wait_bounded`'s follow-up SIGKILL is too, so on the broken kernel both are
 * no-ops and the run would hang. The watchdog is therefore a shared-memory
 * stop flag written by the OBSERVER process and read by the spin loop itself —
 * a plain memory load, syscall-free, so the loop always terminates and the
 * broken kernel produces a DIFFERENT record instead of a hang.
 *
 * `forced=` is that flag, and it is the discriminator on every row here.
 * `handled=`/`outcome=` alone can go green for the wrong reason: once the
 * rescued spinner leaves the loop it makes syscalls again, and the defective
 * kernel then delivers the long-pending signal at that syscall's tail — a
 * SIGKILLed-at-the-end child is indistinguishable from a promptly-killed one
 * by exit status. `forced=1` says the kernel needed userspace to rescue it.
 */
#include "probe.h"

#include <stddef.h>

/* Watchdog page, MAP_SHARED across the fork: `ready` hands the spinner's
 * "handler installed, loop entered" edge to the observer (so the kick can
 * never race an unhandled default disposition), `stop` is the observer's
 * syscall-free release. */
struct spin_shared {
    volatile sig_atomic_t ready;
    volatile sig_atomic_t stop;
};

/* Spinner exit status. Bits, not values: the loop's exit reason and whether
 * the handler ran are independent observations. */
#define SPIN_HANDLED_BIT 1
#define SPIN_STOPPED_BIT 2
#define SPIN_SETUP_FAIL 70

static volatile sig_atomic_t g_hit;
/* The loop's only side effect. Volatile so no compiler may delete the body
 * and turn the spin into a bare flag poll it could hoist. */
static volatile unsigned long g_spin;

static void spin_handler(int sig) { (void)sig; g_hit = 1; }

/* THE case under test: no syscall, no library call, two volatile loads.
 * A kernel that only reaches its delivery point at a syscall tail never
 * interrupts this. */
static void spin_until(volatile sig_atomic_t *stop) {
    while (!g_hit && !*stop) g_spin++;
}

static struct spin_shared *shared_new(void) {
    void *p = mmap(NULL, sizeof(struct spin_shared), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    memset(p, 0, sizeof(struct spin_shared));
    return (struct spin_shared *)p;
}

static void shared_free(struct spin_shared *sh) {
    munmap((void *)sh, sizeof(struct spin_shared));
}

static int install_spin_handler(int sig) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = spin_handler;
    sigemptyset(&sa.sa_mask);
    return sigaction(sig, &sa, NULL);
}

static int wait_ready(struct spin_shared *sh, unsigned ms) {
    long long deadline = mono_ms() + (long long)ms;
    while (!sh->ready) {
        if (mono_ms() >= deadline) return 0;
        sleep_ms(5);
    }
    return 1;
}

/* Reap `pid`, releasing the spin loop from userspace if the kernel would not.
 * Returns 1 iff the release was needed. `*st` is left at 0 when even the
 * release did not end it, which reads as `outcome=blocked`. */
static int collect(pid_t pid, struct spin_shared *sh, int *st) {
    *st = 0;
    if (wait_bounded(pid, SPIN_GUARD_MS, st)) return 0;
    sh->stop = 1;
    if (!wait_bounded(pid, SPIN_RESCUE_MS, st)) {
        kill(pid, SIGKILL);
        wait_bounded(pid, SPIN_RESCUE_MS, st);
    }
    return 1;
}

static int handled_bit(int st) {
    return WIFEXITED(st) && (WEXITSTATUS(st) & SPIN_HANDLED_BIT) ? 1 : 0;
}

/* ------------------------------------------------ 1: peer signal into a spin */

static void usr1_spinner(struct spin_shared *sh) {
    if (install_spin_handler(SIGUSR1) != 0) _exit(SPIN_SETUP_FAIL);
    g_hit = 0;
    sh->ready = 1;
    spin_until(&sh->stop);
    _exit((g_hit ? SPIN_HANDLED_BIT : 0) | (sh->stop ? SPIN_STOPPED_BIT : 0));
}

static void usr1_case(void) {
    struct spin_shared *sh = shared_new();
    if (sh == NULL) { out("spinsig", "usr1_interrupts_spin", "outcome=setup_failed"); return; }
    pid_t pid = fork();
    if (pid == 0) usr1_spinner(sh);
    if (pid < 0) {
        out("spinsig", "usr1_interrupts_spin", "outcome=fork_failed");
        shared_free(sh);
        return;
    }
    if (wait_ready(sh, SPIN_READY_MS)) {
        sleep_ms(SIG_DELAY_MS);
        /* `spinnokick`: no peer signal ever arrives, so a correct kernel has
         * nothing to deliver and the watchdog is what ends the loop — the
         * same record the defective kernel produces. */
        if (!mutant("spinnokick")) kill(pid, SIGUSR1);
    }
    int st = 0;
    int forced = collect(pid, sh, &st);
    out("spinsig", "usr1_interrupts_spin", "handled=%d|forced=%d", handled_bit(st), forced);
    shared_free(sh);
}

/* ------------------------------------------------- 2: own alarm into a spin */

static void alarm_spinner(struct spin_shared *sh) {
    if (install_spin_handler(SIGALRM) != 0) _exit(SPIN_SETUP_FAIL);
    g_hit = 0;
    sh->ready = 1;
    /* `spinnoalarm`: nothing is armed, so the timer path cannot end the loop. */
    if (!mutant("spinnoalarm")) alarm(SPIN_ALARM_S);
    spin_until(&sh->stop);
    alarm(0);
    _exit((g_hit ? SPIN_HANDLED_BIT : 0) | (sh->stop ? SPIN_STOPPED_BIT : 0));
}

/* The spinning task's OWN timer. No peer is involved: the expiry is queued
 * against a task that is on-CPU in userspace, so only a tick that checks for
 * pending signals on its way back to user mode can deliver it. */
static void alarm_case(void) {
    struct spin_shared *sh = shared_new();
    if (sh == NULL) { out("spinsig", "alarm_interrupts_spin", "outcome=setup_failed"); return; }
    pid_t pid = fork();
    if (pid == 0) alarm_spinner(sh);
    if (pid < 0) {
        out("spinsig", "alarm_interrupts_spin", "outcome=fork_failed");
        shared_free(sh);
        return;
    }
    int st = 0;
    int forced = collect(pid, sh, &st);
    out("spinsig", "alarm_interrupts_spin", "delivered=%d|forced=%d", handled_bit(st), forced);
    shared_free(sh);
}

/* ----------------------------------- 3: SIGKILL into a spinning thread group */

/* Own counter per thread: `g_spin` would be a two-thread data race, and the
 * loop only needs a body the compiler may not delete. */
static void *kill_sibling(void *arg) {
    struct spin_shared *sh = (struct spin_shared *)arg;
    volatile unsigned long n = 0;
    sh->ready = 1;
    while (!sh->stop) n++;
    return NULL;
}

/* Neither thread is ever in a syscall while the SIGKILL is sent, so
 * `zap_other_threads`' "kill every thread in the group" has to reach a sibling
 * through its return-to-user path. A group whose leader dies but whose sibling
 * spins on is not reapable, which shows up as the guard firing. */
static void kill_child(struct spin_shared *sh) {
    pthread_t th;
    volatile unsigned long n = 0;
    if (pthread_create(&th, NULL, kill_sibling, sh) != 0) _exit(SPIN_SETUP_FAIL);
    while (!sh->stop) n++;
    pthread_join(th, NULL);
    _exit(SPIN_STOPPED_BIT);
}

static const char *kill_outcome(int st) {
    if (WIFSIGNALED(st)) return WTERMSIG(st) == SIGKILL ? "sigkill" : "signalled";
    if (WIFEXITED(st)) return WEXITSTATUS(st) == SPIN_SETUP_FAIL ? "setup_failed" : "exited";
    return "blocked";
}

static void sigkill_case(void) {
    struct spin_shared *sh = shared_new();
    if (sh == NULL) { out("spinsig", "sigkill_kills_spinning_thread", "outcome=setup_failed|forced=0"); return; }
    pid_t pid = fork();
    if (pid == 0) kill_child(sh);
    if (pid < 0) {
        out("spinsig", "sigkill_kills_spinning_thread", "outcome=fork_failed|forced=0");
        shared_free(sh);
        return;
    }
    if (wait_ready(sh, SPIN_READY_MS)) {
        sleep_ms(SIG_DELAY_MS);
        /* `spinnokill`: the group is never signalled, so only the watchdog
         * ends it — the defective kernel's record, manufactured in userspace. */
        if (!mutant("spinnokill")) kill(pid, SIGKILL);
    }
    int st = 0;
    int forced = collect(pid, sh, &st);
    out("spinsig", "sigkill_kills_spinning_thread", "outcome=%s|forced=%d", kill_outcome(st), forced);
    shared_free(sh);
}

void probe_spinsig(void) {
    usr1_case();
    alarm_case();
    sigkill_case();
}
