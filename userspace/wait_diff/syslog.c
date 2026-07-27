/* syslog(2) SYSLOG_ACTION_READ on an empty ring.
 *
 * `do_syslog` blocks in `wait_event_interruptible(log_wait, ...)`
 * (kernel/printk/printk.c:1611), whose value comes straight from
 * `prepare_to_wait_event` — -ERESTARTSYS. F750 changed oxide from EINTR
 * with no exercise at all.
 *
 * OPT-IN (WAIT_DIFF_SYSLOG=1) because arranging the precondition is
 * DESTRUCTIVE on the oracle: "empty ring" is only reachable by consuming
 * the host's kernel ring with SYSLOG_ACTION_READ, which advances the
 * global syslog cursor for every other reader on that machine, and needs
 * CAP_SYSLOG. A default `make smoke` must not eat the dev box's dmesg, so
 * the case ships disabled and tools/boot-smoke-wait-diff.sh turns it on
 * only when asked.
 */
#include "probe.h"

#define SYSLOG_ACTION_READ        2
#define SYSLOG_ACTION_SIZE_UNREAD 9
#define KMSG_LINE "<6>oxide wait_diff syslog probe\n"

static long sys_syslog(int type, char *buf, int len) {
    return syscall(SYS_syslog, (long)type, (long)buf, (long)len);
}

static int drain(void) {
    char buf[4096];
    for (int i = 0; i < 4096; i++) {
        long unread = sys_syslog(SYSLOG_ACTION_SIZE_UNREAD, NULL, 0);
        if (unread < 0) return -1;
        if (unread == 0) return 0;
        if (sys_syslog(SYSLOG_ACTION_READ, buf, (int)sizeof buf) < 0) return -1;
    }
    return -1;
}

static pid_t spawn_kmsg_writer(void) {
    pid_t pid = fork();
    if (pid != 0) return pid;
    sleep_ms(RELEASE_MS);
    int fd = open("/dev/kmsg", O_WRONLY);
    if (fd < 0) _exit(1);
    if (write(fd, KMSG_LINE, sizeof KMSG_LINE - 1) < 0) _exit(1);
    close(fd);
    _exit(0);
}

void probe_syslog(void) {
    const char *en = getenv("WAIT_DIFF_SYSLOG");
    char buf[4096];
    if (en == NULL || strcmp(en, "1") != 0) {
        out("syslog", "gate", "enabled=0");
        return;
    }
    out("syslog", "gate", "enabled=1");
    if (sys_syslog(SYSLOG_ACTION_SIZE_UNREAD, NULL, 0) < 0) {
        out("syslog", "setup", "unread=denied|errno=%s", errno_name(errno));
        return;
    }
    out("syslog", "drain", "empty=%d", drain() == 0);

    install_handler(SIGALRM, 0);
    arm_timer_ms(SIG_DELAY_MS);
    long rc = sys_syslog(SYSLOG_ACTION_READ, buf, (int)sizeof buf);
    int err = errno;
    disarm_timer();
    out("syslog", "read_empty_norestart", "rc=%d|errno=%s|sig=%d",
        (int)rc, errno_name(rc < 0 ? err : 0), (int)g_sig_count);

    drain();
    pid_t writer = spawn_kmsg_writer();
    install_handler(SIGALRM, 1);
    arm_timer_ms(SIG_DELAY_MS);
    rc = sys_syslog(SYSLOG_ACTION_READ, buf, (int)sizeof buf);
    err = errno;
    disarm_timer();
    out("syslog", "read_empty_sarestart", "rc_gt_zero=%d|errno=%s|sig=%d",
        rc > 0, errno_name(rc < 0 ? err : 0), (int)g_sig_count);
    reap(writer);
}
