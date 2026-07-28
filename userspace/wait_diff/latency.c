/* Timed-wait LATENCY: does a short timeout actually cost what it asked for?
 *
 * Every other case in this harness asserts what the kernel DECIDED. This one
 * asserts how long it TOOK, which is a different and more fragile kind of
 * claim, so it is built to survive TCG jitter three ways:
 *
 *  - repetition. One 1 ms wait is unmeasurable through a bucket; LAT_ITERS of
 *    them are not. A per-wait floor of ~100 ms shows up as ~2 s of total block
 *    time against a ~20 ms request — a 100x error no amount of guest slowness
 *    manufactures.
 *  - two-sided buckets. `ge_req` is the anti-degenerate bound (B1450 found a
 *    CPU-clock sleep that returned INSTANTLY and still reported `outcome=ok`);
 *    `within_budget` is the conformance bound this file exists for. Neither
 *    alone is evidence.
 *  - a budget set against the DEFECT, not against the ideal. LAT_BUDGET_MS is
 *    a quarter of what a per-wait tick floor would cost and roughly twenty
 *    times what a correct kernel spends, so both verdicts sit far from the
 *    edge.
 *
 * B1460: before the wait-expiry queue, `park_with_deadline` only stamped
 * `Task::wakeup_deadline_ns`, whose sole consumer was a registry walk running
 * as a 100 ms periodic on the `ktimers` kthread — and `next_interrupt_deadline`
 * (which programs the one-shot) never saw a wait deadline at all. Every kernel
 * timeout had a ~100 ms floor. These two records are what makes that visible
 * from userspace instead of inferable from klog.
 *
 * Deliberately NOT asserted: the exact latency, or anything about the 50 us
 * slack. Linux may return any time in `[deadline, deadline + slack]` and both
 * kernels are compared against the same host oracle, so only the order of
 * magnitude is a portable claim.
 */
#include "probe.h"

/* Free bits in the 8-bit exit status, above `err_class`'s 5. */
#define LAT_GE_REQ_BIT      32
#define LAT_IN_BUDGET_BIT   64

#define enc err_class
#define dec err_class_name

/* One iteration's wait, run LAT_ITERS times by `measure`. Returns 0 on a
 * clean wait, -1 with errno set otherwise. */
typedef int (*lat_wait_fn)(unsigned ms);

static int wait_nanosleep(unsigned ms) {
    struct timespec req;
    req.tv_sec = 0;
    req.tv_nsec = (long)ms * 1000000L;
    if (ms == 0) return 0;
    return raw_clock_nanosleep(CLOCK_MONOTONIC, 0, &req, NULL);
}

/* epoll_wait on a subscribed-but-never-written pipe: the timeout is the only
 * thing that can end it, so the return is pure wait latency. The child keeps
 * BOTH pipe ends open — closing the write end would make the read end report
 * EPOLLHUP and every `epoll_wait` return immediately, which reads as a latency
 * pass for a kernel that never waited. */
static int g_lat_epfd = -1;

static int wait_epoll(unsigned ms) {
    struct epoll_event ev;
    int rc = epoll_wait(g_lat_epfd, &ev, 1, (int)ms);
    if (rc < 0) return -1;
    if (rc > 0) { errno = EINVAL; return -1; }  /* readiness with no writer */
    return 0;
}

/* Run `f` LAT_ITERS times and collapse the elapsed wall time into two bits.
 * The duration itself never leaves the child — a raw millisecond count is
 * exactly the unbounded-cardinality value the record format forbids. */
static int measure(lat_wait_fn f) {
    /* `latnowait` asks for no wait at all, so the total cannot reach the
     * floor: it is the degenerate implementation the lower bound excludes.
     * `latslow` spends the per-wait tick floor this branch exists to detect,
     * which must blow the budget. */
    unsigned req_ms = LAT_REQ_MS;
    if (mutant("latnowait")) req_ms = 0u;
    if (mutant("latslow")) req_ms = LAT_FLOOR_SIM_MS;
    long long t0 = mono_ms();
    for (unsigned i = 0; i < LAT_ITERS; i++) {
        if (f(req_ms) != 0) return enc(-1, errno);
    }
    long long elapsed = mono_ms() - t0;
    return enc(0, 0)
        | (elapsed >= (long long)(LAT_ITERS * LAT_REQ_MS) ? LAT_GE_REQ_BIT : 0)
        | (elapsed <= (long long)LAT_BUDGET_MS ? LAT_IN_BUDGET_BIT : 0);
}

static void emit(const char *test, int st, int exited) {
    if (!exited) { out("latency", test, "outcome=blocked"); return; }
    out("latency", test, "outcome=%s|ge_req=%d|within_budget=%d",
        dec(st & ~(LAT_GE_REQ_BIT | LAT_IN_BUDGET_BIT)),
        (st & LAT_GE_REQ_BIT) ? 1 : 0,
        (st & LAT_IN_BUDGET_BIT) ? 1 : 0);
}

static void nanosleep_case(void) {
    pid_t pid = fork();
    if (pid == 0) _exit(measure(wait_nanosleep));
    int st = 0;
    if (!wait_bounded(pid, LAT_GUARD_MS, &st) || !WIFEXITED(st)) {
        emit("nanosleep_short", 0, 0);
        return;
    }
    emit("nanosleep_short", WEXITSTATUS(st), 1);
}

static void epoll_case(void) {
    int fds[2];
    if (pipe(fds) < 0) { out("latency", "epoll_wait_short", "outcome=other"); return; }
    pid_t pid = fork();
    if (pid == 0) {
        struct epoll_event sub;
        g_lat_epfd = epoll_create1(0);
        if (g_lat_epfd < 0) _exit(enc(-1, errno));
        sub.events = EPOLLIN;
        sub.data.u32 = 0;
        if (epoll_ctl(g_lat_epfd, EPOLL_CTL_ADD, fds[0], &sub) < 0) _exit(enc(-1, errno));
        _exit(measure(wait_epoll));
    }
    close(fds[0]);
    close(fds[1]);
    int st = 0;
    if (!wait_bounded(pid, LAT_GUARD_MS, &st) || !WIFEXITED(st)) {
        emit("epoll_wait_short", 0, 0);
        return;
    }
    emit("epoll_wait_short", WEXITSTATUS(st), 1);
}

void probe_latency(void) {
    nanosleep_case();
    epoll_case();
}
