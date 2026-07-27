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

    int fd = open_lockfile();
    if (fd < 0) { out("lock", test, "setup=open_failed"); reap(holder); return; }
    install_handler(SIGALRM, restart);
    arm_timer_ms(SIG_DELAY_MS);
    int rc = take(fd, use_fcntl, 1);
    int err = errno;
    disarm_timer();
    out("lock", test, "rc=%d|errno=%s|sig=%d",
        rc, errno_name(rc < 0 ? err : 0), (int)g_sig_count);
    close(fd);
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
