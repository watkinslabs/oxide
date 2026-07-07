// /bin/quota_probe — F4 regression guard: quotactl(2) (nr 179) and
// quotactl_fd(2) (nr 443) must return faithful no-quota-active errnos, NOT
// ENOSYS. On a Linux kernel with quota support compiled in but no fs with
// quotas turned on, Q_SYNC succeeds (nothing to sync) and every query/mutation
// reports "quota not enabled" (ESRCH). oxide has no on-disk quota store, so
// this is the true state — the whole point is ret is NOT -ENOSYS.

#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>

#define PASS "quota_probe: PASS\n"
#define FAIL "quota_probe: FAIL\n"

// linux/quota.h subset (avoid depending on <sys/quota.h> presence).
#define USRQUOTA    0
#define Q_SYNC      0x800001
#define Q_GETQUOTA  0x800007
#define QCMD(cmd, type) (((cmd) << 8) | ((type) & 0xff))

#ifndef SYS_quotactl
#define SYS_quotactl 179
#endif

int main(void) {
    char buf[128];
    memset(buf, 0, sizeof buf);

    // Q_SYNC with NULL special: syncs all quota-enabled fs (none) → 0.
    long r = syscall(SYS_quotactl, QCMD(Q_SYNC, USRQUOTA), (void *)0, 0, (void *)0);
    if (r != 0) { write(1, FAIL, sizeof FAIL - 1); return 1; }

    // Q_GETQUOTA on a real device path: quota not enabled → -1/ESRCH.
    // Must NOT be ENOSYS (that would mean the syscall is unimplemented).
    errno = 0;
    r = syscall(SYS_quotactl, QCMD(Q_GETQUOTA, USRQUOTA), "/dev/root", 0, buf);
    if (!(r == -1 && errno == ESRCH)) { write(1, FAIL, sizeof FAIL - 1); return 1; }

    write(1, PASS, sizeof PASS - 1);
    return 0;
}
