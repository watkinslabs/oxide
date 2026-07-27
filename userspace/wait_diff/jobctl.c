/* tty job control: a background process group reading from its
 * controlling terminal.
 *
 * `__tty_check_change` (drivers/tty/tty_jobctrl.c:55-59) sends SIGTTIN to
 * the background pgrp and returns -ERESTARTSYS *paired with*
 * `set_thread_flag(TIF_SIGPENDING)`, so once SIGCONT resumes the group
 * the read RE-RUNS and — now foreground — succeeds. F749 found oxide
 * returning EINTR here, which made a backgrounded read fail PERMANENTLY
 * instead of resuming after `fg`. Nothing had ever watched that happen.
 *
 * Layout: probe -> session leader (owns the pty, plays the shell) ->
 * background child in its own pgrp (plays the job). Statuses come back
 * through exit codes because only the probe process may print records.
 */
#include "probe.h"

#define TTY_LINE     "hi\n"
#define TTY_LINE_LEN 3

#define RD_EINTR  64
#define RD_ERROR  65
#define STOPPED_BIT 128

static const char *outcome_name(int code) {
    if (code == RD_EINTR) return "eintr";
    if (code == RD_ERROR) return "error";
    return "data";
}

/* Background job: own pgrp, then read the controlling tty. */
static void bg_child(int slave) {
    setpgid(0, 0);
    char b[32];
    ssize_t n = read(slave, b, sizeof b);
    if (n < 0) _exit(errno == EINTR ? RD_EINTR : RD_ERROR);
    _exit((int)(n & 0x3f));
}

/* Session leader: acquire the pty as controlling terminal, start the
 * background job, wait for it to stop on SIGTTIN, foreground it, feed a
 * line, and report what the resumed read returned. */
static void session_child(int master, const char *slave_name) {
    int st = 0, code = RD_ERROR, stopped = 0;
    /* Dispositions survive fork: without this the inherited SIGALRM
     * handler would swallow the guard instead of killing this process. */
    signal(SIGALRM, SIG_DFL);
    alarm(JOBCTL_GUARD_S);
    if (setsid() < 0) _exit(RD_ERROR);
    int slave = open(slave_name, O_RDWR);
    if (slave < 0) _exit(RD_ERROR);
    pid_t bg = fork();
    if (bg == 0) bg_child(slave);
    setpgid(bg, bg);

    if (waitpid(bg, &st, WUNTRACED) < 0) _exit(RD_ERROR);
    stopped = WIFSTOPPED(st) && WSTOPSIG(st) == SIGTTIN;

    if (write(master, TTY_LINE, TTY_LINE_LEN) != TTY_LINE_LEN) _exit(RD_ERROR);
    /* `nofg` mutant: continue the job WITHOUT foregrounding it, so the
     * re-run hits __tty_check_change again and stops again — the guard
     * alarm then converts the case into `timeout`. */
    if (!mutant("nofg") && tcsetpgrp(slave, bg) < 0) _exit(RD_ERROR);
    kill(-bg, SIGCONT);

    if (waitpid(bg, &st, 0) < 0) _exit(RD_ERROR);
    if (WIFEXITED(st)) code = WEXITSTATUS(st);
    _exit((stopped ? STOPPED_BIT : 0) | code);
}

void probe_jobctl(void) {
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0) {
        out("jobctl", "setup", "pty=unavailable|errno=%s", errno_name(errno));
        if (master >= 0) close(master);
        return;
    }
    const char *name = ptsname(master);
    if (name == NULL) {
        out("jobctl", "setup", "pty=no_ptsname|errno=%s", errno_name(errno));
        close(master);
        return;
    }
    out("jobctl", "setup", "pty=ok");
    char slave_name[128];
    snprintf(slave_name, sizeof slave_name, "%s", name);

    pid_t sess = fork();
    if (sess == 0) session_child(master, slave_name);
    int st = 0;
    while (waitpid(sess, &st, 0) < 0 && errno == EINTR) { }
    close(master);

    if (!WIFEXITED(st)) {
        out("jobctl", "sigttin_stops_background", "stopped=unknown");
        out("jobctl", "read_resumes_after_fg", "outcome=timeout|rc=-1");
        return;
    }
    int raw = WEXITSTATUS(st);
    int code = raw & ~STOPPED_BIT;
    out("jobctl", "sigttin_stops_background", "stopped=%d", (raw & STOPPED_BIT) ? 1 : 0);
    out("jobctl", "read_resumes_after_fg", "outcome=%s|rc=%d",
        outcome_name(code), code < RD_EINTR ? code : -1);
}
