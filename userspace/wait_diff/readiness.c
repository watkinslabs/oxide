/* poll(2)/epoll readiness — does a WAKE ever reach a parked waiter?
 *
 * Every case in this file parks a waiter on an EMPTY source and then makes
 * the source non-empty from another process. On Linux the source's own
 * callback does the work: `tty_flip_buffer_push` ->
 * `wake_up_interruptible_poll(&tty->read_wait, EPOLLIN)`
 * (drivers/tty/tty_buffer.c), `pipe_write` ->
 * `wake_up_interruptible_sync_poll(&pipe->rd_wait, EPOLLIN)` (fs/pipe.c),
 * `do_mq_timedsend` -> `__pipelined_op`/`wake_up_interruptible`
 * (ipc/mqueue.c). A kernel that registers the waiter on a wait queue
 * nobody ever wakes parks FOREVER, which is why the poll runs in a child
 * behind `wait_bounded`: the failure mode under test is literally "never
 * returns", and an in-process poll would eat the rest of the run
 * (README §6).
 *
 * `epoll_pty_in` repeats the pty case through epoll_wait. epoll has no
 * rescan: it is armed once by `ep_insert` and thereafter driven ONLY by
 * `ep_poll_callback` firing off the source's wait queue. A kernel that
 * fakes poll(2) by re-polling on a timer tick passes the poll cases and
 * fails this one, so the pair separates "has a wake source" from "gets
 * lucky on a rescan".
 */
#include "probe.h"

#define RDY_MQ_MSGSIZE 64
#define RDY_MQ_MAXMSG  4
#define RDY_LINE     "x\n"
#define RDY_LINE_LEN 2

/* Wait for POLLIN on one fd and hand the class back through the exit code.
 * A newline is used everywhere because the pty SLAVE side is canonical:
 * master->slave input is not deliverable until the line is complete. */
static void poll_in_child(int fd, int use_epoll) {
    int rc = -1;
    int ready_in = 0;
    if (use_epoll) {
        struct epoll_event ev, got;
        int ep = epoll_create1(0);
        if (ep < 0) _exit(RDY_ERROR);
        memset(&ev, 0, sizeof ev);
        ev.events = EPOLLIN;
        ev.data.fd = fd;
        if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) < 0) _exit(RDY_ERROR);
        memset(&got, 0, sizeof got);
        rc = epoll_wait(ep, &got, 1, (int)RDY_POLL_MS);
        ready_in = rc > 0 && (got.events & EPOLLIN) != 0;
    } else {
        struct pollfd p;
        p.fd = fd; p.events = POLLIN; p.revents = 0;
        rc = poll(&p, 1, (int)RDY_POLL_MS);
        ready_in = rc > 0 && (p.revents & POLLIN) != 0;
    }
    if (rc < 0) _exit(RDY_ERROR);
    if (rc == 0) _exit(RDY_TIMEOUT);
    _exit(RDY_OK | (ready_in ? RDY_IN_BIT : 0));
}

/* Make the source non-empty after the waiter has had time to park. The
 * poke lands ~16x before the poll's own timeout, so "ok" and "timeout" are
 * never separated by scheduling latency on a loaded guest. */
static pid_t spawn_poker(int fd, int is_mq) {
    pid_t pid = fork();
    if (pid != 0) return pid;
    sleep_ms(RDY_HELPER_MS);
    /* `nopeerwrite` mutant: never poke the source, so every group-1 record
     * must fall to `outcome=timeout|in=0` — the signature of a kernel with
     * no wake source, produced deliberately. */
    if (!mutant("nopeerwrite")) {
        if (is_mq) {
            char msg[RDY_MQ_MSGSIZE];
            memset(msg, 'x', sizeof msg);
            if (mq_send((mqd_t)fd, msg, sizeof msg, 0) < 0) _exit(1);
        } else if (write(fd, RDY_LINE, RDY_LINE_LEN) != RDY_LINE_LEN) {
            _exit(1);
        }
    }
    _exit(0);
}

static void in_case(const char *test, int poll_fd, int poke_fd,
                    int is_mq, int use_epoll) {
    pid_t poker = spawn_poker(poke_fd, is_mq);
    pid_t waiter = fork();
    if (waiter == 0) poll_in_child(poll_fd, use_epoll);
    int st = 0;
    if (!wait_bounded(waiter, RDY_GUARD_MS, &st)) {
        kill(waiter, SIGKILL); reap(waiter); reap(poker);
        out("ready", test, "outcome=blocked|in=0");
        return;
    }
    reap(poker);
    if (!WIFEXITED(st)) { out("ready", test, "outcome=killed|in=0"); return; }
    int code = WEXITSTATUS(st);
    out("ready", test, "outcome=%s|in=%d",
        rdy_outcome_name(code & 7), (code & RDY_IN_BIT) ? 1 : 0);
}

/* Both ends stay open in the waiter as well as the poker, so a poker that
 * exits without writing (the `nopeerwrite` mutant) cannot masquerade as a
 * wakeup by hanging the peer up. */
static void pty_case(const char *test, int poll_master, int use_epoll) {
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0) {
        out("ready", test, "setup=pty_unavailable|errno=%s", errno_name(errno));
        if (master >= 0) close(master);
        return;
    }
    const char *name = ptsname(master);
    if (name == NULL) {
        out("ready", test, "setup=no_ptsname|errno=%s", errno_name(errno));
        close(master);
        return;
    }
    char slave_name[128];
    snprintf(slave_name, sizeof slave_name, "%s", name);
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
        out("ready", test, "setup=slave_open_failed|errno=%s", errno_name(errno));
        close(master);
        return;
    }
    if (poll_master) in_case(test, master, slave, 0, use_epoll);
    else             in_case(test, slave, master, 0, use_epoll);
    close(slave);
    close(master);
}

static void fifo_case(void) {
    const char *test = "fifo_poll_in";
    char path[128];
    snprintf(path, sizeof path, "/tmp/oxide-wait-diff-ready-%ld.fifo",
             (long)getpid());
    unlink(path);
    if (mkfifo(path, 0600) < 0) {
        out("ready", test, "setup=mkfifo_failed|errno=%s", errno_name(errno));
        return;
    }
    /* O_NONBLOCK on the read end so the open itself does not block waiting
     * for a writer; the WRITE end opens without it because a reader now
     * exists. The waiter inherits the write end, so the source can never
     * reach EOF and report POLLHUP instead of the timeout under test. */
    int rd = open(path, O_RDONLY | O_NONBLOCK);
    if (rd < 0) {
        out("ready", test, "setup=fifo_read_open_failed|errno=%s", errno_name(errno));
        unlink(path);
        return;
    }
    int wr = open(path, O_WRONLY);
    if (wr < 0) {
        out("ready", test, "setup=fifo_write_open_failed|errno=%s", errno_name(errno));
        close(rd);
        unlink(path);
        return;
    }
    in_case(test, rd, wr, 0, 0);
    close(wr);
    close(rd);
    unlink(path);
}

/* A POSIX message queue descriptor is a real file descriptor on Linux
 * (ipc/mqueue.c gives it `mqueue_file_operations.poll`), so it belongs in
 * the same readiness sweep as the pty and the fifo. */
static void mq_case(void) {
    const char *test = "mq_poll_in";
    struct mq_attr attr;
    char name[64];
    snprintf(name, sizeof name, "/wdiff_ready_%ld", (long)getpid());
    memset(&attr, 0, sizeof attr);
    attr.mq_maxmsg  = RDY_MQ_MAXMSG;
    attr.mq_msgsize = RDY_MQ_MSGSIZE;
    mq_unlink(name);
    mqd_t mq = mq_open(name, O_RDWR | O_CREAT, 0600, &attr);
    if (mq == (mqd_t)-1) {
        out("ready", test, "setup=mq_unavailable|errno=%s", errno_name(errno));
        return;
    }
    in_case(test, (int)mq, (int)mq, 1, 0);
    mq_close(mq);
    mq_unlink(name);
}

void probe_readiness(void) {
    pty_case("pty_master_poll_in", 1, 0);
    pty_case("pty_slave_poll_in", 0, 0);
    fifo_case();
    mq_case();
    pty_case("epoll_pty_in", 1, 1);
    probe_readiness_out();
}
