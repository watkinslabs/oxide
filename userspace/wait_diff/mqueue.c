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

#define MQ_SIG_BIT  8
#define MQ_DATA_BIT 16

static void mq_receiver(mqd_t mq, int restart) {
    struct timespec ts;
    char buf[MQ_MSGSIZE];
    abs_deadline(&ts, MQ_ABS_TIMEOUT_S);
    install_handler(SIGALRM, restart);
    arm_timer_ms(SIG_DELAY_MS);
    ssize_t n = mq_timedreceive(mq, buf, sizeof buf, NULL, &ts);
    int cls = err_class((int)n, errno);
    disarm_timer();
    _exit(cls | (g_sig_count ? MQ_SIG_BIT : 0) | (n == MQ_PAYLOAD ? MQ_DATA_BIT : 0));
}

static void recv_case(mqd_t mq, const char *test, int restart) {
    pid_t sender = fork();
    if (sender == 0) {
        char msg[MQ_PAYLOAD];
        memset(msg, 'x', sizeof msg);
        sleep_ms(RELEASE_MS);
        if (mq_send(mq, msg, sizeof msg, 0) < 0) _exit(1);
        _exit(0);
    }
    pid_t rd = fork();
    if (rd == 0) mq_receiver(mq, restart);
    int st = 0;
    if (!wait_bounded(rd, BLOCKED_GUARD_MS, &st)) {
        kill(rd, SIGKILL); reap(rd); reap(sender);
        out("mqueue", test, "outcome=blocked");
    } else {
        reap(sender);
        if (!WIFEXITED(st)) { out("mqueue", test, "outcome=killed"); }
        else {
            int code = WEXITSTATUS(st);
            out("mqueue", test, "outcome=%s|sig=%d|payload=%d",
                err_class_name(code & 7), (code & MQ_SIG_BIT) ? 1 : 0,
                (code & MQ_DATA_BIT) ? 1 : 0);
        }
    }
    /* Drain whatever the sender left behind so the next case starts empty. */
    struct timespec now;
    char buf[MQ_MSGSIZE];
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
