/* Sleep family: nanosleep / clock_nanosleep interruption, remaining-time
 * writeback, and the restart_block continuation.
 *
 * signal(7) puts the sleep interfaces in the NEVER-restarted list: they
 * return -ERESTART_RESTARTBLOCK, which `handle_signal`
 * (arch/x86/kernel/signal.c, arch/arm64/kernel/signal.c) rewrites to
 * -EINTR whenever a HANDLER runs — SA_RESTART or not. The restart_block
 * continuation is therefore reachable only when no handler runs, which is
 * what the stop/cont case exercises. The two `rel_*` cases exist to pin
 * that SA_RESTART changes NOTHING here; a kernel that "helpfully"
 * restarts a sleep under SA_RESTART would lose the remainder writeback.
 */
#include "probe.h"

static void rem_reset(struct timespec *r) {
    r->tv_sec  = REM_SENTINEL_SEC;
    r->tv_nsec = REM_SENTINEL_NSEC;
}

static int rem_untouched(const struct timespec *r) {
    return r->tv_sec == REM_SENTINEL_SEC && r->tv_nsec == REM_SENTINEL_NSEC;
}

static long long ts_ms(const struct timespec *t) {
    return (long long)t->tv_sec * 1000 + t->tv_nsec / 1000000;
}

/* SLEEP_MS exceeds a second (the margin below), so every timespec here has
 * to carry properly: `timespec64_valid` rejects tv_nsec >= 1e9, and a single
 * unconditional carry cannot normalise now+SLEEP_MS once SLEEP_MS itself is
 * over 1e9 ns. */
static void ts_from_ms(struct timespec *t, unsigned ms) {
    t->tv_sec  = (time_t)(ms / 1000u);
    t->tv_nsec = (long)((ms % 1000u) * 1000000L);
}

static void ts_add_ms(struct timespec *t, unsigned ms) {
    t->tv_sec  += (time_t)(ms / 1000u);
    t->tv_nsec += (long)((ms % 1000u) * 1000000L);
    while (t->tv_nsec >= 1000000000L) { t->tv_nsec -= 1000000000L; t->tv_sec++; }
}

static void report_rel(const char *test, int rc, int err,
                       const struct timespec *req, const struct timespec *rem) {
    int written = !rem_untouched(rem);
    out("sleep", test, "rc=%d|errno=%s|sig=%d|rem_written=%d|rem_lt_req=%d|rem_gt_zero=%d",
        rc, errno_name(err), (int)g_sig_count, written,
        written && ts_ms(rem) < ts_ms(req),
        written && (rem->tv_sec > 0 || rem->tv_nsec > 0));
}

static void rel_case(const char *test, int restart) {
    struct timespec req, rem;
    ts_from_ms(&req, SLEEP_MS);
    rem_reset(&rem);
    install_handler(SIGALRM, restart);
    arm_timer_ms(SIG_DELAY_MS);
    int rc = raw_clock_nanosleep(CLOCK_MONOTONIC, 0, &req, &rem);
    int err = errno;
    disarm_timer();
    report_rel(test, rc, rc < 0 ? err : 0, &req, &rem);
}

/* TIMER_ABSTIME must NOT write rem — the caller already holds the
 * absolute deadline, so there is nothing to hand back
 * (kernel/time/hrtimer.c: `if (!t->task) ... else if (rmtp)` is reached
 * only on the relative path). The `absrem` mutant runs this case
 * relatively, which flips rem_written and fails the diff. */
static void abs_case(void) {
    struct timespec now, req, rem;
    clock_gettime(CLOCK_MONOTONIC, &now);
    req = now;
    ts_add_ms(&req, SLEEP_MS);
    rem_reset(&rem);
    install_handler(SIGALRM, 1);
    arm_timer_ms(SIG_DELAY_MS);
    int flags = mutant("absrem") ? 0 : TIMER_ABSTIME;
    struct timespec relreq;
    ts_from_ms(&relreq, SLEEP_MS);
    int rc = raw_clock_nanosleep(CLOCK_MONOTONIC, flags,
                                 flags ? &req : &relreq, &rem);
    int err = errno;
    disarm_timer();
    out("sleep", "abs_sarestart", "rc=%d|errno=%s|sig=%d|rem_written=%d",
        rc, errno_name(rc < 0 ? err : 0), (int)g_sig_count, !rem_untouched(&rem));
}

/* No handler runs, so the -ERESTART_RESTARTBLOCK survives signal delivery
 * and `restart_syscall` re-enters the sleep against the ABSOLUTE expiry
 * stashed in the restart block. Linux therefore completes the sleep
 * (rc=0) and never touches rem. A kernel without the continuation reports
 * EINTR here. The `handler` mutant replaces the stop/cont pair with a
 * handled SIGUSR1, i.e. exactly the case where the continuation must NOT
 * run — it flips rc to -1/EINTR.
 *
 * The sleeper is a CHILD, not the probe itself: a probe process that
 * SIGSTOPs itself is reported as a stopped job by whatever shell drives
 * the harness, which ends the run. */
#define SC_EINTR    1
#define SC_OTHER    2
#define SC_SIG_BIT  4
#define SC_REM_BIT  8

static void stopcont_sleeper(int use_handler) {
    struct timespec req, rem;
    pid_t self = getpid();
    pid_t helper = fork();
    if (helper == 0) {
        sleep_ms(STOP_MS);
        if (use_handler) { kill(self, SIGUSR1); _exit(0); }
        kill(self, SIGSTOP);
        sleep_ms(CONT_MS - STOP_MS);
        kill(self, SIGCONT);
        _exit(0);
    }
    ts_from_ms(&req, SLEEP_MS);
    rem_reset(&rem);
    if (use_handler) install_handler(SIGUSR1, 1);
    g_sig_count = 0;
    int rc = raw_clock_nanosleep(CLOCK_MONOTONIC, 0, &req, &rem);
    int err = errno;
    reap(helper);
    int code = rc == 0 ? 0 : (err == EINTR ? SC_EINTR : SC_OTHER);
    if (g_sig_count) code |= SC_SIG_BIT;
    if (!rem_untouched(&rem)) code |= SC_REM_BIT;
    _exit(code);
}

static void stopcont_case(void) {
    pid_t pid = fork();
    if (pid == 0) stopcont_sleeper(mutant("handler"));
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
    if (!WIFEXITED(st)) { out("sleep", "stopcont_restart_block", "outcome=killed"); return; }
    int code = WEXITSTATUS(st);
    int cls = code & 3;
    out("sleep", "stopcont_restart_block", "rc=%d|errno=%s|sig=%d|rem_written=%d",
        cls == 0 ? 0 : -1,
        cls == 0 ? "OK" : (cls == SC_EINTR ? "EINTR" : "OTHER"),
        (code & SC_SIG_BIT) ? 1 : 0, (code & SC_REM_BIT) ? 1 : 0);
}

void probe_sleep(void) {
    rel_case("rel_norestart", 0);
    rel_case("rel_sarestart", 1);
    abs_case();
    stopcont_case();
}
