/* System V message queues: the SLEEPING halves of msgsnd(2)/msgrcv(2) and
 * the msgtyp selection rules.
 *
 * Both parks return -ERESTARTNOHAND (`ipc/msg.c:930` for the sender,
 * `ipc/msg.c:1241` for the receiver), which is the one restart class a
 * DELIVERED handler always converts to EINTR regardless of SA_RESTART —
 * so the two `*_signal_*` records per direction are deliberately
 * identical, and the restart itself is only observable when no handler
 * runs. The `*_stopcont_*` cases are that observation: SIGSTOP/SIGCONT
 * makes signal_pending true with no handler frame, so a correct kernel
 * re-enters the call and still completes it.
 */
#include "probe.h"

#include <sys/ipc.h>
#include <sys/msg.h>

#define MSG_MODE     0600
#define MSG_BIG      8192   /* MSGMAX: two of these fill a default queue */
#define MSG_PAYLOAD  5
#define MSG_SMALL    8
#define MSG_SHORT    4
/* The stop/cont peer acts only after the SIGCONT, so a completed call
 * proves the syscall was re-entered rather than merely resumed early. */
#define MSG_LATE_MS  1500u

struct mtext_big { long mtype; char mtext[MSG_BIG]; };
struct mtext_small { long mtype; char mtext[MSG_SMALL]; };

static struct mtext_big g_big;

static int msg_new(void) { return msgget(IPC_PRIVATE, IPC_CREAT | IPC_EXCL | MSG_MODE); }
static void msg_kill(int id) { if (id >= 0) msgctl(id, IPC_RMID, NULL); }

static int send_n(int id, long mtype, size_t n, int flg) {
    memset(&g_big, 'x', sizeof g_big);
    g_big.mtype = mtype;
    return msgsnd(id, &g_big, n, flg);
}

/* Two MSGMAX messages reach q_qbytes exactly, so the next send of any
 * size cannot fit. */
static void fill_queue(int id) {
    send_n(id, 1, MSG_BIG, 0);
    send_n(id, 1, MSG_BIG, 0);
}

/* Free one slot for a parked sender. IPC_NOWAIT because the caller always
 * queued the message it is taking back: a blocking drain in the PARENT
 * would park the probe itself if a mutant ever changed that assumption,
 * and one wedged parent costs every record behind it. */
static void drain_one(int id) {
    struct mtext_big buf;
    msgrcv(id, &buf, MSG_BIG, 1, IPC_NOWAIT);
}

/* See `sysv_sem.c`: `slept` is only reported where a real wait is the
 * assertion. An interrupted case would be reporting guest wake latency. */
static void report_child(const char *test, pid_t pid, unsigned guard_ms, int want_slept) {
    int st = 0;
    const char *cls = "blocked";
    int slept = 0, sig = 0, data = 0;
    if (!wait_bounded(pid, guard_ms, &st)) {
        kill(pid, SIGKILL);
        reap(pid);
    } else if (!WIFEXITED(st)) {
        cls = "killed";
    } else {
        int code = WEXITSTATUS(st);
        cls = sysv_class_name(code & SV_CLS_MASK);
        slept = (code & SV_SLEPT) ? 1 : 0;
        sig = (code & SV_SIG) ? 1 : 0;
        data = (code & SV_DATA) ? 1 : 0;
    }
    if (want_slept) out("sysv_msg", test, "outcome=%s|slept=%d|sig=%d|payload=%d", cls, slept, sig, data);
    else            out("sysv_msg", test, "outcome=%s|sig=%d|payload=%d", cls, sig, data);
}

/* `sig` < 0 installs no handler; otherwise it is the SA_RESTART argument
 * and an itimer fires inside the park. */
static void rcv_child(int id, int sig) {
    struct mtext_big buf;
    long long t0;
    /* fork inherits the counter from earlier probes; a case with no
     * handler must still report sig=0. */
    g_sig_count = 0;
    if (sig >= 0) { install_handler(SIGALRM, sig); arm_timer_ms(SIG_DELAY_MS); }
    t0 = mono_ms();
    ssize_t n = msgrcv(id, &buf, MSG_BIG, 0, 0);
    int err = errno;
    disarm_timer();
    int code = sysv_class((int)n, err);
    if (mono_ms() - t0 >= (long long)SYSV_SLEPT_MS) code |= SV_SLEPT;
    if (g_sig_count) code |= SV_SIG;
    if (n == MSG_PAYLOAD) code |= SV_DATA;
    _exit(code);
}

static void snd_child(int id, int sig) {
    long long t0;
    g_sig_count = 0;
    if (sig >= 0) { install_handler(SIGALRM, sig); arm_timer_ms(SIG_DELAY_MS); }
    t0 = mono_ms();
    int rc = send_n(id, 2, MSG_PAYLOAD, 0);
    int err = errno;
    disarm_timer();
    int code = sysv_class(rc, err);
    if (mono_ms() - t0 >= (long long)SYSV_SLEPT_MS) code |= SV_SLEPT;
    if (g_sig_count) code |= SV_SIG;
    if (rc == 0) code |= SV_DATA;
    _exit(code);
}

static void rcv_nowait(void) {
    int id = msg_new();
    if (id < 0) { out("sysv_msg", "rcv_nowait_enomsg", "outcome=setup_failed|slept=0|sig=0|payload=0"); return; }
    if (mutant("sysvavail")) send_n(id, 1, MSG_PAYLOAD, 0);
    struct mtext_big buf;
    ssize_t n = msgrcv(id, &buf, MSG_BIG, 0, IPC_NOWAIT);
    out("sysv_msg", "rcv_nowait_enomsg", "outcome=%s|slept=0|sig=0|payload=%d",
        sysv_class_name(sysv_class((int)n, errno)), n == MSG_PAYLOAD ? 1 : 0);
    msg_kill(id);
}

static void snd_nowait(void) {
    int id = msg_new();
    if (id < 0) { out("sysv_msg", "snd_nowait_eagain", "outcome=setup_failed|slept=0|sig=0|payload=0"); return; }
    /* `sysvavail` leaves the queue empty, so the same call succeeds. */
    if (!mutant("sysvavail")) fill_queue(id);
    int rc = send_n(id, 2, MSG_PAYLOAD, IPC_NOWAIT);
    out("sysv_msg", "snd_nowait_eagain", "outcome=%s|slept=0|sig=0|payload=%d",
        sysv_class_name(sysv_class(rc, errno)), rc == 0 ? 1 : 0);
    msg_kill(id);
}

static void rcv_blocks(void) {
    int id = msg_new();
    if (id < 0) { out("sysv_msg", "rcv_blocks_until_sent", "outcome=setup_failed|slept=0|sig=0|payload=0"); return; }
    pid_t pid = fork();
    if (pid == 0) rcv_child(id, -1);
    sleep_ms(SYSV_RELEASE_MS);
    if (!mutant("sysvnopost")) send_n(id, 1, MSG_PAYLOAD, 0);
    report_child("rcv_blocks_until_sent", pid, SYSV_GUARD_MS, 1);
    msg_kill(id);
}

static void snd_blocks(void) {
    int id = msg_new();
    if (id < 0) { out("sysv_msg", "snd_blocks_until_drained", "outcome=setup_failed|slept=0|sig=0|payload=0"); return; }
    send_n(id, 1, MSG_BIG, 0);
    send_n(id, 1, MSG_BIG, 0);
    pid_t pid = fork();
    if (pid == 0) snd_child(id, -1);
    sleep_ms(SYSV_RELEASE_MS);
    if (!mutant("sysvnopost")) drain_one(id);
    report_child("snd_blocks_until_drained", pid, SYSV_GUARD_MS, 1);
    msg_kill(id);
}

static void signal_case(const char *test, int restart, int sender) {
    int id = msg_new();
    if (id < 0) { out("sysv_msg", test, "outcome=setup_failed|sig=0|payload=0"); return; }
    if (sender) fill_queue(id);
    pid_t pid = fork();
    if (pid == 0) { if (sender) snd_child(id, restart); else rcv_child(id, restart); }
    report_child(test, pid, SYSV_GUARD_MS, 0);
    msg_kill(id);
}

/* No handler runs, so -ERESTARTNOHAND survives signal delivery and the
 * call is re-entered; the peer acts only after the SIGCONT, so a kernel
 * that returned EINTR here records `eintr` with no payload. The `handler`
 * mutant replaces the stop/cont pair with a handled SIGUSR1, which is
 * exactly the case that must NOT restart. */
static void stopcont_child(int id, int sender) {
    int use_handler = mutant("handler");
    pid_t self = getpid();
    pid_t helper = fork();
    if (helper == 0) {
        sleep_ms(SYSV_STOP_MS);
        if (use_handler) { kill(self, SIGUSR1); _exit(0); }
        kill(self, SIGSTOP);
        sleep_ms(SYSV_CONT_MS - SYSV_STOP_MS);
        kill(self, SIGCONT);
        _exit(0);
    }
    if (use_handler) install_handler(SIGUSR1, 1);
    g_sig_count = 0;
    long long t0 = mono_ms();
    int rc;
    if (sender) rc = send_n(id, 2, MSG_PAYLOAD, 0);
    else {
        struct mtext_big buf;
        rc = (int)msgrcv(id, &buf, MSG_BIG, 0, 0);
    }
    int err = errno;
    reap(helper);
    int code = sysv_class(rc, err);
    if (mono_ms() - t0 >= (long long)SYSV_SLEPT_MS) code |= SV_SLEPT;
    if (g_sig_count) code |= SV_SIG;
    if (sender ? rc == 0 : rc == MSG_PAYLOAD) code |= SV_DATA;
    _exit(code);
}

static void stopcont_case(const char *test, int sender) {
    int id = msg_new();
    if (id < 0) { out("sysv_msg", test, "outcome=setup_failed|slept=0|sig=0|payload=0"); return; }
    if (sender) fill_queue(id);
    pid_t pid = fork();
    if (pid == 0) stopcont_child(id, sender);
    sleep_ms(MSG_LATE_MS);
    if (sender) drain_one(id);
    else send_n(id, 1, MSG_PAYLOAD, 0);
    report_child(test, pid, SYSV_GUARD_MS, 1);
    msg_kill(id);
}

static void rmid_case(void) {
    int id = msg_new();
    if (id < 0) { out("sysv_msg", "rmid_eidrm", "outcome=setup_failed|slept=0|sig=0|payload=0"); return; }
    pid_t pid = fork();
    if (pid == 0) rcv_child(id, -1);
    sleep_ms(SYSV_SETTLE_MS);
    if (!mutant("sysvnormid")) msg_kill(id);
    report_child("rmid_eidrm", pid, SYSV_GUARD_MS, 1);
    msg_kill(id);
}

/* A message too big for the buffer is E2BIG and STAYS QUEUED; with
 * MSG_NOERROR the same call truncates instead. `sysvmsgflags` drops the
 * flag, which turns the truncation record back into E2BIG. */
static void size_cases(void) {
    int id = msg_new();
    if (id < 0) {
        out("sysv_msg", "rcv_e2big", "outcome=setup_failed|got=-1|still_queued=0");
        out("sysv_msg", "rcv_noerror_truncates", "outcome=setup_failed|got=-1");
        return;
    }
    struct mtext_small buf;
    send_n(id, 1, MSG_SMALL, 0);
    ssize_t n = msgrcv(id, &buf, MSG_SHORT, 0, 0);
    int cls = sysv_class((int)n, errno);
    ssize_t probe = msgrcv(id, &buf, MSG_SMALL, 0, IPC_NOWAIT);
    out("sysv_msg", "rcv_e2big", "outcome=%s|got=%d|still_queued=%d",
        sysv_class_name(cls), (int)n, probe == MSG_SMALL ? 1 : 0);

    send_n(id, 1, MSG_SMALL, 0);
    int flg = mutant("sysvmsgflags") ? 0 : MSG_NOERROR;
    n = msgrcv(id, &buf, MSG_SHORT, 0, flg);
    out("sysv_msg", "rcv_noerror_truncates", "outcome=%s|got=%d",
        sysv_class_name(sysv_class((int)n, errno)), (int)n);
    msg_kill(id);
}

/* A negative msgtyp selects the LOWEST type <= |msgtyp|, not the first
 * match, so a queue filled 3,1,2 drains 1,2,3. `sysvmsgflags` asks for
 * type 0 instead, which drains in FIFO order. */
static void type_cases(void) {
    int id = msg_new();
    if (id < 0) {
        out("sysv_msg", "negative_msgtyp_lowest", "first=-1|second=-1|third=-1");
        out("sysv_msg", "msg_except_skips", "got=-1");
        return;
    }
    struct mtext_small buf;
    long want = mutant("sysvmsgflags") ? 0 : -3;
    long got[3];
    send_n(id, 3, MSG_PAYLOAD, 0);
    send_n(id, 1, MSG_PAYLOAD, 0);
    send_n(id, 2, MSG_PAYLOAD, 0);
    for (int i = 0; i < 3; i++) {
        buf.mtype = 0;
        got[i] = msgrcv(id, &buf, MSG_PAYLOAD, want, 0) < 0 ? -1 : buf.mtype;
    }
    out("sysv_msg", "negative_msgtyp_lowest", "first=%ld|second=%ld|third=%ld",
        got[0], got[1], got[2]);

    send_n(id, 1, MSG_PAYLOAD, 0);
    send_n(id, 2, MSG_PAYLOAD, 0);
    buf.mtype = 0;
    int flg = mutant("sysvmsgflags") ? 0 : MSG_EXCEPT;
    long g = msgrcv(id, &buf, MSG_PAYLOAD, 1, flg) < 0 ? -1 : buf.mtype;
    out("sysv_msg", "msg_except_skips", "got=%ld", g);
    msg_kill(id);
}

void probe_sysv_msg(void) {
    int probe = msg_new();
    if (probe < 0) {
        out("sysv_msg", "setup", "msg=unavailable|errno=%s", errno_name(errno));
        return;
    }
    msg_kill(probe);
    out("sysv_msg", "setup", "msg=ok");
    rcv_nowait();
    snd_nowait();
    rcv_blocks();
    snd_blocks();
    signal_case("rcv_signal_sarestart", 1, 0);
    signal_case("rcv_signal_norestart", 0, 0);
    signal_case("snd_signal_sarestart", 1, 1);
    signal_case("snd_signal_norestart", 0, 1);
    stopcont_case("rcv_stopcont_restarts", 0);
    stopcont_case("snd_stopcont_restarts", 1);
    rmid_case();
    size_cases();
    type_cases();
}
