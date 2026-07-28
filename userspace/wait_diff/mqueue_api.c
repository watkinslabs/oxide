/* POSIX message queues: the non-blocking API surface — the `mq_open`/
 * `mq_unlink`/`mq_notify`/`mq_getsetattr` errno ladders, priority ordering,
 * and notification delivery.
 *
 * `mqueue.c` next door covers the BLOCKING edge. This file covers everything
 * a wrong `mq_open` ladder gets away with while the blocking edge looks fine:
 * before F760 oxide accepted every name, ignored `O_CREAT`/`O_EXCL`, ignored
 * the access mode, silently CLAMPED an out-of-range `mq_attr` instead of
 * rejecting it, rejected `SIGEV_NONE`, and registered notifications it then
 * delivered with no siginfo. Each of those is a record here.
 *
 * Determinism rule (probe.h): nothing here may depend on uid or on the
 * caller's capabilities — the oracle runs as an ordinary user and the guest
 * runs as root, so a `CAP_SYS_RESOURCE`-gated limit or a sticky-directory
 * ownership test would diverge for reasons unrelated to the semantics under
 * test. Every case below is decided identically for root and non-root.
 */
#include "probe.h"

#define API_NAME    "/oxide_wdiff_api"
#define API_MSGSIZE 64
#define API_MAXMSG  4
/* MQ_PRIO_MAX (include/uapi/linux/mqueue.h): msg_prio must be strictly less. */
#define API_PRIO_MAX 32768
/* SI_MESGQ (asm-generic/siginfo.h) — the si_code an mq notification carries. */
#define API_SIVAL   0x5a5a
#define NOTIFY_WAIT_S 3

static mqd_t api_create(int oflag, long maxmsg, long msgsize) {
    struct mq_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.mq_maxmsg = maxmsg;
    attr.mq_msgsize = msgsize;
    return mq_open(API_NAME, oflag, 0600, &attr);
}

static int e(int rc) { return rc < 0 ? errno : 0; }

static void name_rules(void) {
    char longname[300];
    longname[0] = '/';
    memset(longname + 1, 'q', sizeof longname - 2);
    longname[sizeof longname - 1] = '\0';

    errno = 0; int no_slash = e((int)mq_open("oxide_wdiff_noslash", O_RDWR | O_CREAT, 0600, NULL));
    errno = 0; int embedded = e((int)mq_open("/oxide/wdiff", O_RDWR | O_CREAT, 0600, NULL));
    errno = 0; int dot      = e((int)mq_open("/.", O_RDWR | O_CREAT, 0600, NULL));
    errno = 0; int dotdot   = e((int)mq_open("/..", O_RDWR | O_CREAT, 0600, NULL));
    errno = 0; int toolong  = e((int)mq_open(longname, O_RDWR | O_CREAT, 0600, NULL));
    errno = 0; int empty    = e((int)mq_open("/", O_RDWR | O_CREAT, 0600, NULL));
    out("mqapi", "name_rules",
        "no_slash=%s|embedded=%s|dot=%s|dotdot=%s|toolong=%s|empty=%s",
        errno_name(no_slash), errno_name(embedded), errno_name(dot),
        errno_name(dotdot), errno_name(toolong), errno_name(empty));
}

static void existence_rules(void) {
    mq_unlink(API_NAME);
    errno = 0; int noent = e((int)mq_open(API_NAME, O_RDWR, 0600, NULL));
    mqd_t mq = api_create(O_RDWR | O_CREAT | O_EXCL, API_MAXMSG, API_MSGSIZE);
    int created = (mq != (mqd_t)-1);
    errno = 0; int excl = e((int)api_create(O_RDWR | O_CREAT | O_EXCL, API_MAXMSG, API_MSGSIZE));
    /* O_CREAT alone on an existing queue opens it and IGNORES the attr. */
    mqd_t again = api_create(O_RDWR | O_CREAT, 1, 8);
    struct mq_attr got;
    int attr_kept = 0;
    if (again != (mqd_t)-1 && mq_getattr(again, &got) == 0)
        attr_kept = (got.mq_maxmsg == API_MAXMSG && got.mq_msgsize == API_MSGSIZE);
    if (again != (mqd_t)-1) mq_close(again);
    /* An mq descriptor is installed with O_CLOEXEC unconditionally
     * (ipc/mqueue.c:924 `FD_ADD(O_CLOEXEC, ...)`), whatever oflag asked. */
    int cloexec = created ? ((fcntl(mq, F_GETFD) & FD_CLOEXEC) ? 1 : 0) : -1;
    if (created) mq_close(mq);
    out("mqapi", "existence_rules",
        "noent=%s|created=%d|excl=%s|attr_of_existing_kept=%d|cloexec=%d",
        errno_name(noent), created, errno_name(excl), attr_kept, cloexec);
}

static void attr_rules(void) {
    mq_unlink(API_NAME);
    errno = 0; int zero_max  = e((int)api_create(O_RDWR | O_CREAT, 0, API_MSGSIZE));
    errno = 0; int zero_size = e((int)api_create(O_RDWR | O_CREAT, API_MAXMSG, 0));
    errno = 0; int neg       = e((int)api_create(O_RDWR | O_CREAT, -1, API_MSGSIZE));
    /* Past HARD_MSGMAX / HARD_MSGSIZEMAX, which even CAP_SYS_RESOURCE cannot
     * pass — so the answer is the same for the oracle and for the guest. */
    errno = 0; int huge_max  = e((int)api_create(O_RDWR | O_CREAT, 65537, API_MSGSIZE));
    errno = 0; int huge_size = e((int)api_create(O_RDWR | O_CREAT, API_MAXMSG,
                                                 16L * 1024 * 1024 + 1));
    out("mqapi", "attr_rules",
        "zero_max=%s|zero_size=%s|negative=%s|over_hard_max=%s|over_hard_size=%s",
        errno_name(zero_max), errno_name(zero_size), errno_name(neg),
        errno_name(huge_max), errno_name(huge_size));
}

static void attr_readback(mqd_t mq) {
    struct mq_attr got, set, old;
    memset(&got, 0, sizeof got);
    int rc = mq_getattr(mq, &got);
    /* mq_flags is the DESCRIPTION's O_NONBLOCK, and only that bit is settable. */
    memset(&set, 0, sizeof set);
    set.mq_flags = O_NONBLOCK;
    memset(&old, 0, sizeof old);
    int set_rc = mq_setattr(mq, &set, &old);
    struct mq_attr after;
    memset(&after, 0, sizeof after);
    mq_getattr(mq, &after);
    int fcntl_view = (fcntl(mq, F_GETFL) & O_NONBLOCK) ? 1 : 0;
    /* Now non-blocking on an empty queue: EAGAIN, not a park. */
    char buf[API_MSGSIZE];
    errno = 0; int recv_eagain = e((int)mq_receive(mq, buf, sizeof buf, NULL));
    /* Any other bit in mq_flags is EINVAL. */
    memset(&set, 0, sizeof set);
    set.mq_flags = O_NONBLOCK | O_APPEND;
    errno = 0; int badbit = e(mq_setattr(mq, &set, NULL));
    /* Put it back and confirm the round trip. */
    memset(&set, 0, sizeof set);
    mq_setattr(mq, &set, NULL);
    int cleared = (fcntl(mq, F_GETFL) & O_NONBLOCK) ? 1 : 0;
    out("mqapi", "attr_readback",
        "get=%d|maxmsg=%ld|msgsize=%ld|curmsgs=%ld|old_flags=%ld|set=%d"
        "|now_nonblock=%ld|fcntl_view=%d|recv=%s|badbit=%s|cleared=%d",
        rc, got.mq_maxmsg, got.mq_msgsize, got.mq_curmsgs, old.mq_flags, set_rc,
        after.mq_flags & O_NONBLOCK ? 1L : 0L, fcntl_view,
        errno_name(recv_eagain), errno_name(badbit), cleared);
}

static void priority_order(mqd_t mq) {
    /* Highest priority first, FIFO within one priority. `mqnoprio` flattens
     * every send to priority 0, which must change this record. */
    static const struct { char c; unsigned p; } send[] = {
        { 'a', 1 }, { 'b', 10 }, { 'c', 10 }, { 'd', 5 },
    };
    for (unsigned i = 0; i < sizeof send / sizeof send[0]; i++) {
        char m = send[i].c;
        unsigned p = mutant("mqnoprio") ? 0u : send[i].p;
        if (mq_send(mq, &m, 1, p) < 0) { out("mqapi", "priority_order", "send=%s",
                                             errno_name(errno)); return; }
    }
    char order[8] = {0}, prios[32] = {0};
    size_t at = 0;
    for (unsigned i = 0; i < sizeof send / sizeof send[0]; i++) {
        char buf[API_MSGSIZE];
        unsigned prio = 0;
        ssize_t n = mq_receive(mq, buf, sizeof buf, &prio);
        if (n != 1) { out("mqapi", "priority_order", "recv=%s", errno_name(errno)); return; }
        order[i] = buf[0];
        at += (size_t)snprintf(prios + at, sizeof prios - at, i ? ",%u" : "%u", prio);
    }
    out("mqapi", "priority_order", "order=%s|prios=%s", order, prios);
}

static void size_and_prio_limits(mqd_t mq) {
    char big[API_MSGSIZE + 1];
    memset(big, 'x', sizeof big);
    errno = 0; int send_big = e((int)mq_send(mq, big, sizeof big, 0));
    errno = 0; int prio_max = e((int)mq_send(mq, big, 1, API_PRIO_MAX));
    int prio_ok = (int)mq_send(mq, big, 1, API_PRIO_MAX - 1);
    /* The receive buffer must fit ANY message the queue may hold, not just
     * the one at its head (ipc/mqueue.c:1175). */
    char small[API_MSGSIZE - 1];
    errno = 0; int recv_small = e((int)mq_receive(mq, small, sizeof small, NULL));
    char buf[API_MSGSIZE];
    unsigned got = 0;
    ssize_t drained = mq_receive(mq, buf, sizeof buf, &got);
    out("mqapi", "size_and_prio_limits",
        "send_over_msgsize=%s|prio_at_max=%s|prio_below_max=%d|recv_short_buf=%s"
        "|drained=%zd|drained_prio=%u",
        errno_name(send_big), errno_name(prio_max), prio_ok < 0 ? -1 : 0,
        errno_name(recv_small), drained, got);
}

static void read_state_line(mqd_t mq) {
    /* `mqueue_read_file` (ipc/mqueue.c:629-656): read(2) on an mq descriptor
     * reports the queue's state in a fixed-width line, and mqueuefs has NO
     * write method at all, so write(2) is EINVAL. Registering AFTER the send
     * keeps the registration alive for the read — `__do_notify` unregisters on
     * the 0->1 transition, so arming first would report an empty owner. */
    char m = 'r';
    /* `mqnostate` leaves the queue empty, so QSIZE must change. */
    int sent = mutant("mqnostate") ? -1 : (int)mq_send(mq, &m, 1, 3);
    struct sigevent sev;
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGUSR2;
    int armed = e(mq_notify(mq, &sev));
    char line[128];
    memset(line, 0, sizeof line);
    ssize_t n = read(mq, line, sizeof line - 1);
    unsigned long qsize = 0;
    int notify = -1, signo = -1;
    long pid = -1;
    int fields = n > 0 ? sscanf(line, "QSIZE:%lu NOTIFY:%d SIGNO:%d NOTIFY_PID:%ld",
                                &qsize, &notify, &signo, &pid) : -1;
    errno = 0; int wr = e((int)write(mq, &m, 1));
    mq_notify(mq, NULL);
    char buf[API_MSGSIZE];
    if (sent == 0) mq_receive(mq, buf, sizeof buf, NULL);
    /* The LINE LENGTH is not deterministic — `NOTIFY_PID:%-6d` overflows its
     * width for a 7-digit pid, and the oracle's pids are far larger than the
     * guest's. The byte offset of the last field is: it pins every preceding
     * `%-10lu` / `%-5d` pad without depending on any pid. */
    const char *tail = n > 0 ? strstr(line, "NOTIFY_PID:") : NULL;
    out("mqapi", "read_state_line",
        "armed=%s|pid_off=%d|fields=%d|qsize=%lu|notify=%d|signo=%d|pid_is_self=%d|write=%s",
        errno_name(armed), tail ? (int)(tail - line) : -1, fields, qsize, notify, signo,
        pid == (long)getpid() ? 1 : 0, errno_name(wr));
}

static void access_mode(void) {
    mqd_t ro = mq_open(API_NAME, O_RDONLY);
    mqd_t wo = mq_open(API_NAME, O_WRONLY);
    char buf[API_MSGSIZE];
    errno = 0; int ro_send = e((int)mq_send(ro, buf, 1, 0));
    errno = 0; int wo_recv = e((int)mq_receive(wo, buf, sizeof buf, NULL));
    /* O_ACCMODE (3) on an EXISTING queue is EINVAL (ipc/mqueue.c:882). */
    errno = 0; int accmode3 = e((int)mq_open(API_NAME, O_RDWR | O_WRONLY));
    if (ro != (mqd_t)-1) mq_close(ro);
    if (wo != (mqd_t)-1) mq_close(wo);
    out("mqapi", "access_mode", "rdonly_send=%s|wronly_recv=%s|accmode3=%s",
        errno_name(ro_send), errno_name(wo_recv), errno_name(accmode3));
}

static void unlink_semantics(void) {
    mq_unlink(API_NAME);
    mqd_t mq = api_create(O_RDWR | O_CREAT | O_EXCL, API_MAXMSG, API_MSGSIZE);
    if (mq == (mqd_t)-1) { out("mqapi", "unlink_semantics", "setup=%s", errno_name(errno)); return; }
    int first = e(mq_unlink(API_NAME));
    errno = 0; int second = e(mq_unlink(API_NAME));
    /* POSIX: an unlinked queue stays fully usable through descriptors that
     * were already open. */
    char m = 'z', buf[API_MSGSIZE];
    int still_send = e((int)mq_send(mq, &m, 1, 0));
    ssize_t n = mq_receive(mq, buf, sizeof buf, NULL);
    errno = 0; int reopen = e((int)mq_open(API_NAME, O_RDWR));
    mq_close(mq);
    out("mqapi", "unlink_semantics",
        "first=%s|second=%s|send_after_unlink=%s|recv_after_unlink=%zd|reopen=%s",
        errno_name(first), errno_name(second), errno_name(still_send), n,
        errno_name(reopen));
}

static void notify_validation(mqd_t mq) {
    struct sigevent sev;
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = 99;
    errno = 0; int badmode = e(mq_notify(mq, &sev));
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = 65;
    errno = 0; int badsig = e(mq_notify(mq, &sev));
    /* SIGEV_NONE is a REAL registration: it takes the queue's single slot and
     * delivers nothing (ipc/mqueue.c:1346-1348, :787). */
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_NONE;
    errno = 0; int none = e(mq_notify(mq, &sev));
    errno = 0; int busy = e(mq_notify(mq, &sev));
    errno = 0; int clear = e(mq_notify(mq, NULL));
    errno = 0; int rearm = e(mq_notify(mq, &sev));
    mq_notify(mq, NULL);
    out("mqapi", "notify_validation",
        "badmode=%s|badsig=%s|sigev_none=%s|second=%s|clear=%s|rearm=%s",
        errno_name(badmode), errno_name(badsig), errno_name(none),
        errno_name(busy), errno_name(clear), errno_name(rearm));
}

static void notify_signal(mqd_t mq) {
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    sigprocmask(SIG_BLOCK, &block, &old);

    struct sigevent sev;
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGUSR1;
    sev.sigev_value.sival_int = API_SIVAL;
    int armed = e(mq_notify(mq, &sev));

    char m = 'n';
    /* `mqnonotify` skips the send, so the record must lose its delivery. */
    int sent = mutant("mqnonotify") ? -1 : (int)mq_send(mq, &m, 1, 0);

    siginfo_t info;
    memset(&info, 0, sizeof info);
    struct timespec ts = { .tv_sec = NOTIFY_WAIT_S, .tv_nsec = 0 };
    int got = sigtimedwait(&block, &info, &ts);
    int delivered = (got == SIGUSR1);
    /* One-shot: delivery unregisters, so the slot is free again. */
    int rearm = e(mq_notify(mq, &sev));
    mq_notify(mq, NULL);

    char buf[API_MSGSIZE];
    if (sent == 0) mq_receive(mq, buf, sizeof buf, NULL);
    sigprocmask(SIG_SETMASK, &old, NULL);
    out("mqapi", "notify_signal",
        "armed=%s|delivered=%d|si_code_mesgq=%d|sival=%d|oneshot_rearm=%s",
        errno_name(armed), delivered,
        delivered && info.si_code == SI_MESGQ ? 1 : 0,
        delivered && info.si_value.sival_int == API_SIVAL ? 1 : 0,
        errno_name(rearm));
}

static volatile sig_atomic_t g_thread_fired;
static void notify_thread_fn(union sigval v) { (void)v; g_thread_fired = 1; }

static void notify_thread(mqd_t mq) {
    /* glibc implements SIGEV_THREAD by handing the kernel an AF_NETLINK
     * socket in sigev_signo plus a 32-byte cookie in sigev_value.sival_ptr;
     * `__do_notify` echoes the cookie back on that socket and glibc's helper
     * thread runs the callback (ipc/mqueue.c:1287-1318, :824-827). A kernel
     * that ACCEPTS the registration and never echoes is the "accepted but
     * never delivered" lie this record exists to catch. */
    struct sigevent sev;
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = notify_thread_fn;
    sev.sigev_notify_attributes = NULL;
    g_thread_fired = 0;
    int armed = e(mq_notify(mq, &sev));
    char m = 't';
    int sent = mutant("mqnothread") ? -1 : (int)mq_send(mq, &m, 1, 0);
    for (unsigned i = 0; i < NOTIFY_WAIT_S * 20u && !g_thread_fired; i++) sleep_ms(50);
    int fired = g_thread_fired ? 1 : 0;
    if (!fired) mq_notify(mq, NULL);
    char buf[API_MSGSIZE];
    if (sent == 0) mq_receive(mq, buf, sizeof buf, NULL);
    out("mqapi", "notify_thread", "armed=%s|fired=%d", errno_name(armed), fired);
}

void probe_mqueue_api(void) {
    name_rules();
    existence_rules();
    attr_rules();
    mq_unlink(API_NAME);
    mqd_t mq = api_create(O_RDWR | O_CREAT | O_EXCL, API_MAXMSG, API_MSGSIZE);
    if (mq == (mqd_t)-1) {
        out("mqapi", "setup", "mq=unavailable|errno=%s", errno_name(errno));
        return;
    }
    out("mqapi", "setup", "mq=ok");
    attr_readback(mq);
    priority_order(mq);
    size_and_prio_limits(mq);
    read_state_line(mq);
    access_mode();
    notify_validation(mq);
    notify_signal(mq);
    notify_thread(mq);
    mq_close(mq);
    unlink_semantics();
    mq_unlink(API_NAME);
}
