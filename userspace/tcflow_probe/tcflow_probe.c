// /bin/tcflow_probe — B119 regression guard: TCXONC (tcflow(3), ioctl
// 0x540A) software output flow control must be REAL, not a fake success.
// Linux tcflow(fd, action): TCOOFF suspends output, TCOON resumes it,
// TCIOFF/TCION transmit a STOP/START char. Pre-B119 the kernel returned 0
// for every action without doing anything. This probe asserts:
//   1. tcflow(TCOON)  → 0 (valid action accepted),
//   2. tcflow(99)     → -1/EINVAL (out-of-range action rejected, NOT a
//      silent success — the must-not-regress behaviour),
//   3. tcflow(TCOOFF) then tcflow(TCOON) → 0,0, and a write AFTER TCOON
//      proceeds and returns the byte count (output resumed, not wedged).
//
// HANG-SAFETY: a blocking write to a tty while output is suspended parks
// forever by design, so the probe NEVER writes while stopped — it resumes
// (TCOON) before the verifying write. A SIGALRM watchdog converts any
// unexpected park into FAIL rather than a hung probe / hung boot.

#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>

#define PASS "tcflow_probe: PASS\n"
#define FAIL "tcflow_probe: FAIL\n"

static void on_alrm(int s) {
    (void)s;
    // Watchdog tripped: a write/ioctl wedged. Report FAIL and exit hard so
    // the boot smoke does not stall.
    write(2, FAIL, sizeof FAIL - 1);
    _exit(1);
}

int main(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alrm;                 // no SA_RESTART: a wedge trips
    sigaction(SIGALRM, &sa, 0);

    int fd = 1;                              // stdout — our controlling tty

    // (1) valid action accepted.
    alarm(3);
    if (tcflow(fd, TCOON) != 0) {
        write(2, FAIL, sizeof FAIL - 1); return 1;
    }

    // (2) out-of-range action must be EINVAL, not a fake success. ioctl()
    // directly so we bypass any libc-side argument clamping.
    errno = 0;
    if (ioctl(fd, TCXONC, 99) != -1 || errno != EINVAL) {
        write(2, FAIL, sizeof FAIL - 1); return 1;
    }

    // (3) suspend then resume, then a write must proceed. We do NOT write
    // between TCOOFF and TCOON (that would park by design); the watchdog
    // above guards against TCOON failing to wake the write path.
    if (tcflow(fd, TCOOFF) != 0) {
        write(2, FAIL, sizeof FAIL - 1); return 1;
    }
    if (tcflow(fd, TCOON) != 0) {
        write(2, FAIL, sizeof FAIL - 1); return 1;
    }
    char ok = '.';
    if (write(fd, &ok, 1) != 1) {            // must not park (output resumed)
        write(2, FAIL, sizeof FAIL - 1); return 1;
    }

    alarm(0);
    write(1, PASS, sizeof PASS - 1);
    return 0;
}
