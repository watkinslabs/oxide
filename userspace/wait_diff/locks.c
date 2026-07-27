/* File locking: `flock(LOCK_EX)` and `fcntl(F_SETLKW)` under real
 * contention.
 *
 * fs/locks.c contains no -EINTR and no -ERESTARTSYS at all: every lock
 * wait is a bare `wait_event_interruptible` whose value propagates
 * unchanged from `prepare_to_wait_event` (kernel/sched/wait.c:309), i.e.
 * -ERESTARTSYS. So SA_RESTART must make the blocked lock RESUME and
 * eventually acquire, and its absence must surface EINTR. F750 changed
 * both sites from EINTR to ERESTARTSYS with no runtime exercise; this is
 * that exercise.
 */
#include "probe.h"

#define LOCK_PATH "/tmp/oxide-wait-diff.lock"

static int open_lockfile(void) { return open(LOCK_PATH, O_RDWR | O_CREAT, 0600); }

static int take(int fd, int use_fcntl, int wait) {
    if (!use_fcntl) return flock(fd, LOCK_EX | (wait ? 0 : LOCK_NB));
    struct flock fl;
    memset(&fl, 0, sizeof fl);
    fl.l_type = F_WRLCK; fl.l_whence = SEEK_SET; fl.l_start = 0; fl.l_len = 1;
    return fcntl(fd, wait ? F_SETLKW : F_SETLK, &fl);
}

/* Holds the lock for RELEASE_MS, then exits — the exit is what releases
 * it, so the parent's blocked acquire completes only if it survived the
 * signal. */
static pid_t spawn_holder(int use_fcntl, int syncfd) {
    pid_t pid = fork();
    if (pid != 0) return pid;
    int fd = open_lockfile();
    if (fd < 0 || take(fd, use_fcntl, 1) < 0) { wr1(syncfd, 'e'); _exit(1); }
    wr1(syncfd, 'k');
    sleep_ms(RELEASE_MS);
    _exit(0);
}

#define LK_SIG_BIT 8

/* The blocking acquire runs in a CHILD behind `wait_bounded`. F753 found
 * `fcntl(F_SETLKW)` blocking PAST the holder's release in oxide, which as
 * an in-process call simply hung the probe and cost every record behind
 * it. As a child it becomes `outcome=blocked`, which is the finding. */
static void acquirer(int use_fcntl, int restart) {
    int fd = open_lockfile();
    if (fd < 0) _exit(CLS_OTHER);
    install_handler(SIGALRM, restart);
    arm_timer_ms(SIG_DELAY_MS);
    int rc = take(fd, use_fcntl, 1);
    int cls = err_class(rc, errno);
    disarm_timer();
    close(fd);
    _exit(cls | (g_sig_count ? LK_SIG_BIT : 0));
}

static void lock_case(const char *test, int use_fcntl, int restart) {
    int sync[2];
    char c = 0;
    if (pipe(sync) < 0) { out("lock", test, "setup=pipe_failed"); return; }
    pid_t holder = spawn_holder(use_fcntl, sync[1]);
    close(sync[1]);
    if (read(sync[0], &c, 1) != 1 || c != 'k') {
        out("lock", test, "setup=holder_failed");
        close(sync[0]); reap(holder); return;
    }
    close(sync[0]);

    pid_t pid = fork();
    if (pid == 0) acquirer(use_fcntl, restart);
    int st = 0;
    if (!wait_bounded(pid, BLOCKED_GUARD_MS, &st)) {
        kill(pid, SIGKILL);
        reap(pid);
        out("lock", test, "outcome=blocked");
        reap(holder);
        return;
    }
    if (!WIFEXITED(st)) { out("lock", test, "outcome=killed"); reap(holder); return; }
    int code = WEXITSTATUS(st);
    out("lock", test, "outcome=%s|sig=%d",
        err_class_name(code & ~LK_SIG_BIT), (code & LK_SIG_BIT) ? 1 : 0);
    reap(holder);
}

void probe_locks(void) {
    int fd = open_lockfile();
    if (fd < 0) {
        out("lock", "setup", "lockfile=unavailable|errno=%s", errno_name(errno));
        return;
    }
    close(fd);
    out("lock", "setup", "lockfile=ok");
    lock_case("flock_sarestart",  0, 1);
    lock_case("flock_norestart",  0, 0);
    lock_case("setlkw_sarestart", 1, 1);
    lock_case("setlkw_norestart", 1, 0);
    unlink(LOCK_PATH);
}
