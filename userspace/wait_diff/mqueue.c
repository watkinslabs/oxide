/* POSIX message queues: the kill path and the restart path.
 *
 * `wq_sleep` (ipc/mqueue.c:739) returns -ERESTARTSYS, so a blocked
 * mq_timedreceive under SA_RESTART must resume. Before F745/F747 oxide's
 * mq_timedsend/mq_timedreceive had NO signal check at all — an UNKILLABLE
 * park, strictly worse than a wrong errno. The kill case therefore has a
 * bounded wait: "still alive after the deadline" is the observable that
 * names that bug, and a plain blocking waitpid would instead hang the
 * whole probe.
 */
#include "probe.h"

#define MQ_NAME    "/oxide_wait_diff"
#define MQ_MSGSIZE 64
#define MQ_PAYLOAD 5

static void abs_deadline(struct timespec *ts, int secs) {
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += secs;
}

/* Reap within `ms`, else report the child as still parked. */
static int wait_bounded(pid_t pid, unsigned ms, int *st) {
    long long deadline = mono_ms() + (long long)ms;
    for (;;) {
        pid_t r = waitpid(pid, st, WNOHANG);
        if (r == pid) return 1;
        if (r < 0 && errno != EINTR) return 0;
        if (mono_ms() >= deadline) return 0;
        sleep_ms(20);
    }
}

static const char *sig_name(int s) {
    switch (s) {
    case SIGKILL: return "SIGKILL";
    case SIGTERM: return "SIGTERM";
    case SIGALRM: return "SIGALRM";
    default: return "OTHER";
    }
}

static void kill_case(mqd_t mq) {
    struct timespec ts;
    pid_t pid = fork();
    if (pid == 0) {
        char buf[MQ_MSGSIZE];
        abs_deadline(&ts, MQ_ABS_TIMEOUT_S);
        mq_timedreceive(mq, buf, sizeof buf, NULL, &ts);
        _exit(0);
    }
    sleep_ms(KILL_DELAY_MS);
    /* `mqnokill` mutant: never signal, so the bounded wait reports the
     * same `parked` outcome an unkillable park would produce. */
    if (!mutant("mqnokill")) kill(pid, SIGKILL);
    int st = 0;
    if (!wait_bounded(pid, 5000u, &st)) {
        kill(pid, SIGKILL);
        reap(pid);
        out("mqueue", "sigkill_kills_blocked_receiver", "outcome=parked");
        return;
    }
    out("mqueue", "sigkill_kills_blocked_receiver", "outcome=%s|termsig=%s",
        WIFSIGNALED(st) ? "signalled" : "exited",
        sig_name(WIFSIGNALED(st) ? WTERMSIG(st) : 0));
}

static void recv_case(mqd_t mq, const char *test, int restart) {
    pid_t pid = fork();
    if (pid == 0) {
        char msg[MQ_PAYLOAD];
        memset(msg, 'x', sizeof msg);
        sleep_ms(RELEASE_MS);
        if (mq_send(mq, msg, sizeof msg, 0) < 0) _exit(1);
        _exit(0);
    }
    struct timespec ts;
    char buf[MQ_MSGSIZE];
    abs_deadline(&ts, MQ_ABS_TIMEOUT_S);
    install_handler(SIGALRM, restart);
    arm_timer_ms(SIG_DELAY_MS);
    ssize_t n = mq_timedreceive(mq, buf, sizeof buf, NULL, &ts);
    int err = errno;
    disarm_timer();
    out("mqueue", test, "rc=%d|errno=%s|sig=%d",
        (int)n, errno_name(n < 0 ? err : 0), (int)g_sig_count);
    reap(pid);
    /* Drain whatever the writer left behind so the next case starts empty. */
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    while (mq_timedreceive(mq, buf, sizeof buf, NULL, &now) >= 0) { }
}

void probe_mqueue(void) {
    struct mq_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.mq_maxmsg = 1;
    attr.mq_msgsize = MQ_MSGSIZE;
    mq_unlink(MQ_NAME);
    mqd_t mq = mq_open(MQ_NAME, O_RDWR | O_CREAT | O_EXCL, 0600, &attr);
    if (mq == (mqd_t)-1) {
        out("mqueue", "setup", "mq=unavailable|errno=%s", errno_name(errno));
        return;
    }
    out("mqueue", "setup", "mq=ok");
    kill_case(mq);
    recv_case(mq, "recv_sarestart", 1);
    recv_case(mq, "recv_norestart", 0);
    mq_close(mq);
    mq_unlink(MQ_NAME);
}
