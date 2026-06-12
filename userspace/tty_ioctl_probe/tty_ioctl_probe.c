// /bin/tty_ioctl_probe — B120 regression guard: tty modem + pts-lock ioctls
// must be REAL, not fake successes.
//
// Pre-B120 fakes (crates/kernel/syscalls/src/016_ioctl.rs):
//   TIOCSPTLCK => 0;                    // ignored, slave always openable
//   TIOCMGET   => hardcoded healthy mask (ignored prior SET);
//   TIOCMSET|TIOCMBIS|TIOCMBIC => 0;    // discarded.
//
// Linux contract asserted here:
//   1. /dev/ptmx allocates a pts LOCKED — opening the slave returns EIO
//      until unlockpt() (TIOCSPTLCK 0). TIOCGPTLCK reads the lock state.
//   2. Re-locking (TIOCSPTLCK !=0) makes a fresh slave open EIO again.
//   3. A pty master has no modem lines → TIOCMGET = ENOTTY.
//   4. The serial console implements tiocmget/tiocmset over a software MCR:
//      carrier (TIOCM_CAR) is strapped present; TIOCMBIC clears DTR in the
//      shadow and TIOCMGET reflects it; TIOCMBIS restores it.
//
// A SIGALRM watchdog turns any unexpected park into FAIL, not a hung boot.

#define _XOPEN_SOURCE 600   // posix_openpt / ptsname (musl)
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

#ifndef TIOCGPTLCK
#define TIOCGPTLCK 0x80045439
#endif
#ifndef TIOCM_DTR
#define TIOCM_DTR  0x002
#endif
#ifndef TIOCM_CAR
#define TIOCM_CAR  0x040
#endif

#define PASS "tty_ioctl_probe: PASS\n"
#define FAIL "tty_ioctl_probe: FAIL\n"

static void fail(const char *why) {
    write(2, FAIL, sizeof FAIL - 1);
    write(2, why, strlen(why));
    write(2, "\n", 1);
    _exit(1);
}
static void on_alrm(int s) { (void)s; fail("watchdog"); }

int main(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alrm;
    sigaction(SIGALRM, &sa, 0);
    alarm(5);

    // (1) ptmx → master; pts created LOCKED.
    int mfd = posix_openpt(O_RDWR | O_NOCTTY);
    if (mfd < 0) fail("posix_openpt");
    int ptn = -1;
    if (ioctl(mfd, TIOCGPTN, &ptn) != 0 || ptn < 0) fail("TIOCGPTN");
    char path[64];
    snprintf(path, sizeof path, "/dev/pts/%d", ptn);

    // slave open while locked → EIO.
    errno = 0;
    int s = open(path, O_RDWR | O_NOCTTY);
    if (s >= 0 || errno != EIO) { if (s >= 0) close(s); fail("locked slave openable"); }

    // TIOCGPTLCK reads 1 while locked.
    int lck = -1;
    if (ioctl(mfd, TIOCGPTLCK, &lck) != 0 || lck != 1) fail("TIOCGPTLCK!=1");

    // unlockpt (TIOCSPTLCK 0); readback 0; slave now opens.
    int zero = 0;
    if (ioctl(mfd, TIOCSPTLCK, &zero) != 0) fail("unlockpt");
    if (ioctl(mfd, TIOCGPTLCK, &lck) != 0 || lck != 0) fail("TIOCGPTLCK!=0");
    int sfd = open(path, O_RDWR | O_NOCTTY);
    if (sfd < 0) fail("unlocked slave open");
    close(sfd);

    // (2) re-lock → fresh slave open EIO again.
    int one = 1;
    if (ioctl(mfd, TIOCSPTLCK, &one) != 0) fail("relock");
    errno = 0;
    int s2 = open(path, O_RDWR | O_NOCTTY);
    if (s2 >= 0 || errno != EIO) { if (s2 >= 0) close(s2); fail("relocked slave openable"); }

    // (3) pty master has no modem lines → ENOTTY.
    int mbits; errno = 0;
    if (ioctl(mfd, TIOCMGET, &mbits) != -1 || errno != ENOTTY) fail("pty TIOCMGET not ENOTTY");
    close(mfd);

    // (4) serial console (stdout): real modem register.
    int sbits;
    if (ioctl(1, TIOCMGET, &sbits) != 0) fail("serial TIOCMGET");
    if (!(sbits & TIOCM_CAR)) fail("carrier not strapped");
    int dtr = TIOCM_DTR;
    if (ioctl(1, TIOCMBIC, &dtr) != 0) fail("TIOCMBIC");
    int after;
    if (ioctl(1, TIOCMGET, &after) != 0) fail("TIOCMGET-2");
    if (after & TIOCM_DTR) fail("DTR not cleared");   // SET must take effect
    if (ioctl(1, TIOCMBIS, &dtr) != 0) fail("TIOCMBIS");
    if (ioctl(1, TIOCMGET, &after) != 0) fail("TIOCMGET-3");
    if (!(after & TIOCM_DTR)) fail("DTR not restored");

    alarm(0);
    write(1, PASS, sizeof PASS - 1);
    return 0;
}
