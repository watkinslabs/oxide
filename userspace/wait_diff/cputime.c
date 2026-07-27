/* CPU-time sleeps: `clock_nanosleep` on a CPU clock.
 *
 * Linux never converts a CPU clock to a wall deadline. `do_cpu_nanosleep`
 * (kernel/time/posix-cpu-timers.c:1537-1626) arms a stack k_itimer with
 * `it.cpu.nanosleep = true` so `cpu_timer_fire` (:684-688) WAKES the
 * sleeper off the accounting path instead of queueing a signal. Two
 * consequences this file pins:
 *
 *  - a single-threaded process sleeping on CLOCK_PROCESS_CPUTIME_ID
 *    accrues no CPU while asleep, so nothing advances the clock and the
 *    sleep never completes. That reads like a hang and IS Linux's
 *    behaviour; the guard signal is what makes it observable.
 *  - a sibling burning CPU DOES advance it, so the same sleep completes.
 *    This holds on one CPU too — the sleeper is blocked, so the burner
 *    has the CPU to itself.
 *
 * F751 landed both without a live exercise. The `wallcpu` mutant restores
 * the pre-F751 wall-clock conversion, which flips case 1 from eintr to ok.
 */
#include "probe.h"

#define CPU_SLEPT_BIT 32

static volatile int g_burn_stop = 0;

#define enc err_class
#define dec err_class_name

static void cpu_sleep_req(struct timespec *req) {
    req->tv_sec = 0;
    req->tv_nsec = (long)CPU_SLEEP_MS * 1000000L;
}

/* Case 1 — nothing advances the process clock, so only the guard signal
 * ends the sleep. */
static void no_progress_case(void) {
    pid_t pid = fork();
    if (pid == 0) {
        struct timespec req;
        cpu_sleep_req(&req);
        clockid_t clk = mutant("wallcpu") ? CLOCK_MONOTONIC : CLOCK_PROCESS_CPUTIME_ID;
        install_handler(SIGALRM, 0);
        arm_timer_ms(CPU_GUARD_MS);
        int rc = raw_clock_nanosleep(clk, 0, &req, NULL);
        _exit(enc(rc, errno));
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
    out("cputime", "single_thread_no_progress", "outcome=%s",
        WIFEXITED(st) ? dec(WEXITSTATUS(st)) : "killed");
}

static void *burner(void *arg) {
    (void)arg;
    volatile unsigned long x = 0;
    long long deadline = mono_ms() + (long long)CPU_BURN_GUARD_MS;
    while (!g_burn_stop && mono_ms() < deadline) {
        for (int i = 0; i < 100000; i++) x += (unsigned long)i;
    }
    return NULL;
}

/* Case 2 — a sibling thread burning CPU advances the process clock, so
 * the same sleep completes on CONSUMED cpu time.
 *
 * `outcome=ok` alone is NOT sufficient evidence: B1450 found oxide's CPU
 * sleep returning 0 IMMEDIATELY (an unresolved clock id sampled as None,
 * so the call never armed or parked), which made this case read as a
 * match while the syscall did nothing at all. The elapsed bucket is what
 * separates "slept on consumed cpu time" from "returned instantly" — a
 * real sleep cannot finish before the cpu time it waited for was spent. */
static void sibling_burn_case(void) {
    pid_t pid = fork();
    if (pid == 0) {
        struct timespec req;
        pthread_t th;
        sigset_t block, prev;
        cpu_sleep_req(&req);
        install_handler(SIGALRM, 0);
        arm_timer_ms(CPU_BURN_GUARD_MS + 1000u);
        /* Keep the process-directed guard signal off the burner thread so
         * the sleeper is always the one that observes it. */
        sigemptyset(&block);
        sigaddset(&block, SIGALRM);
        pthread_sigmask(SIG_BLOCK, &block, &prev);
        int started = mutant("noburn") ? -1 : pthread_create(&th, NULL, burner, NULL);
        pthread_sigmask(SIG_SETMASK, &prev, NULL);
        long long t0 = mono_ms();
        int rc = raw_clock_nanosleep(CLOCK_PROCESS_CPUTIME_ID, 0, &req, NULL);
        long long elapsed = mono_ms() - t0;
        int code = enc(rc, errno);
        g_burn_stop = 1;
        if (started == 0) pthread_join(th, NULL);
        _exit(code | (elapsed >= (long long)CPU_SLEEP_MS ? CPU_SLEPT_BIT : 0));
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
    if (!WIFEXITED(st)) { out("cputime", "sibling_burn_completes", "outcome=killed"); return; }
    int code = WEXITSTATUS(st);
    out("cputime", "sibling_burn_completes", "outcome=%s|slept=%d",
        dec(code & ~CPU_SLEPT_BIT), (code & CPU_SLEPT_BIT) ? 1 : 0);
}

/* Case 3 — the static per-thread CPU clock has no `.nsleep` in Linux's
 * `clock_thread` k_clock table (posix-cpu-timers.c:1727-1731), so
 * clock_nanosleep rejects it before any wait happens. */
static void thread_clock_case(void) {
    struct timespec req;
    req.tv_sec = 0; req.tv_nsec = 1000000L;
    int rc = raw_clock_nanosleep(CLOCK_THREAD_CPUTIME_ID, 0, &req, NULL);
    out("cputime", "thread_cputime_nsleep", "outcome=%s", dec(enc(rc, errno)));
}

void probe_cputime(void) {
    thread_clock_case();
    no_progress_case();
    sibling_burn_case();
}
