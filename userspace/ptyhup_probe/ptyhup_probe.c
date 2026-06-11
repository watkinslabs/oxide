// /bin/ptyhup_probe — pty MASTER-close → slave EOF regression (console-plan B5e).
//
// Proves the kernel wires the tty hangup mechanism to a REAL close: when the
// last fd on the pty MASTER side closes (terminal emulator / ssh / script
// exiting), the slave's next read returns 0 (EOF). Before B5e the master
// close did nothing and the slave reader hung forever — the SIGALRM timeout
// converts that into a printed FAIL instead of a wedged boot.
//
//   PARENT: posix_openpt + grantpt + unlockpt + ptsname; fork; write a byte
//           to the master (child sees it), then CLOSE the master fd.
//   CHILD : open the slave (/dev/pts/N), read in a loop; the read AFTER the
//           master close MUST return 0 (EOF) → exit 0 (PASS signal).
//
// PASS iff the child's post-close read returns 0 (EOF).

#define _XOPEN_SOURCE 600   // posix_openpt/grantpt/unlockpt/ptsname (musl)
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

static volatile sig_atomic_t timed_out = 0;
static void on_alrm(int s) { (void)s; timed_out = 1; }

static void emit(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alrm;            // no SA_RESTART → blocked read() returns EINTR
    sigaction(SIGALRM, &sa, 0);
    sigaction(SIGCHLD, &(struct sigaction){.sa_handler = SIG_DFL}, 0);
    alarm(5);

    int mfd = posix_openpt(O_RDWR | O_NOCTTY);
    if (mfd < 0) { emit("ptyhup_probe: FAIL (posix_openpt)\n"); return 1; }
    if (grantpt(mfd) != 0)  { emit("ptyhup_probe: FAIL (grantpt)\n");  return 1; }
    if (unlockpt(mfd) != 0) { emit("ptyhup_probe: FAIL (unlockpt)\n"); return 1; }
    const char *sname = ptsname(mfd);
    if (!sname) { emit("ptyhup_probe: FAIL (ptsname)\n"); return 1; }

    // Capture the slave path before fork so the child inherits it.
    char spath[64];
    strncpy(spath, sname, sizeof spath - 1);
    spath[sizeof spath - 1] = '\0';

    pid_t pid = fork();
    if (pid < 0) { emit("ptyhup_probe: FAIL (fork)\n"); return 1; }

    if (pid == 0) {
        // CHILD: open the slave, read the parent's byte, then read again —
        // the second read must return 0 (EOF) once the master has closed.
        int sfd = open(spath, O_RDWR | O_NOCTTY);
        if (sfd < 0) { _exit(2); }       // open failed
        char c;
        long n = read(sfd, &c, 1);       // the byte the parent wrote
        if (n != 1 || c != 'X') { _exit(3); }
        // Next read blocks until the master closes, then returns 0 (EOF).
        n = read(sfd, &c, 1);
        if (timed_out)  { _exit(4); }    // hung — hangup never fired
        if (n == 0) { _exit(0); }        // EOF after master close → PASS
        _exit(5);                        // unexpected data / error
    }

    // PARENT: hand the child a byte, give it a moment to read it, then close
    // the master fd — that last-close must hang up the slave.
    write(mfd, "X", 1);
    // Spin briefly so the child consumes the byte before we hang up. The
    // child's FIRST read must succeed before the close, else it would race
    // the EOF. usleep is enough; the alarm bounds the whole run.
    usleep(100 * 1000);
    close(mfd);

    int status = 0;
    pid_t w = waitpid(pid, &status, 0);
    alarm(0);
    if (timed_out) { emit("ptyhup_probe: FAIL (timeout)\n"); return 1; }
    if (w == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        emit("ptyhup_probe: PASS\n");
        return 0;
    }
    emit("ptyhup_probe: FAIL (slave did not see EOF)\n");
    return 1;
}
