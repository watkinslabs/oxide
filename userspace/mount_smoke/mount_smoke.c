// /bin/mount_smoke — K2 mount acceptance (runs as root from rcS).
//   1. mount(NULL,"/",NULL,MS_REC|MS_SHARED) — systemd's early
//      mount-setup propagation call; must return 0 (not EFAULT on the
//      NULL fstype/source).
//   2. MS_BIND: bind /etc onto /tmp/eb, then read /tmp/eb/hostname and
//      confirm it matches /etc/hostname (the bind redirect works).

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <errno.h>

#ifndef MS_BIND
#define MS_BIND   0x1000
#endif
#ifndef MS_REC
#define MS_REC    0x4000
#endif
#ifndef MS_SHARED
#define MS_SHARED (1u<<20)
#endif

#define PASS "mount_smoke: PASS\n"
static int fail(const char *why) {
    char b[96]; int n = snprintf(b, sizeof b, "mount_smoke: FAIL %s errno=%d\n", why, errno);
    write(1, b, n);
    return 1;
}

static int slurp(const char *p, char *buf, int cap) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    int n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    return n;
}

int main(void) {
    // 1. propagation change on / — systemd issues this very early.
    if (mount(NULL, "/", NULL, MS_REC | MS_SHARED, NULL) != 0)
        return fail("propagation");

    // 2. bind /etc onto /tmp/eb and read through the bind.
    mkdir("/tmp/eb", 0755);
    if (mount("/etc", "/tmp/eb", NULL, MS_BIND, NULL) != 0)
        return fail("bind");

    char direct[256], viabind[256];
    int dn = slurp("/etc/hostname", direct, sizeof direct);
    int bn = slurp("/tmp/eb/hostname", viabind, sizeof viabind);
    if (dn <= 0) return fail("read-direct");
    if (bn <= 0) return fail("read-bind");
    if (dn != bn || memcmp(direct, viabind, dn) != 0) return fail("bind-mismatch");

    write(1, PASS, sizeof(PASS) - 1);
    return 0;
}
