// /bin/dev_smoke — standard /dev fd-symlinks acceptance.
//   1. readlink /dev/{stdin,stdout,stderr,fd} → /proc/self/fd/{0,1,2}
//      and /proc/self/fd. Proves the nodes exist as symlinks.
//   2. open("/dev/stdout", O_WRONLY) and write — proves the kernel
//      FOLLOWS the symlink (/dev/stdout → /proc/self/fd/1 → the real
//      console), not just readlinks it. Before open()-time symlink
//      following this open returned the link inode and the write
//      failed.

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static int fails = 0;

static void want_link(const char *path, const char *want) {
    char buf[128];
    ssize_t n = readlink(path, buf, sizeof buf - 1);
    if (n < 0) { printf("dev_smoke: FAIL readlink(%s) errno=%d\n", path, errno); fails++; return; }
    buf[n] = '\0';
    if (strcmp(buf, want) != 0) {
        printf("dev_smoke: FAIL %s -> '%s' want '%s'\n", path, buf, want);
        fails++;
    } else {
        printf("dev_smoke: ok %s -> %s\n", path, buf);
    }
}

int main(void) {
    want_link("/dev/stdin",  "/proc/self/fd/0");
    want_link("/dev/stdout", "/proc/self/fd/1");
    want_link("/dev/stderr", "/proc/self/fd/2");
    want_link("/dev/fd",     "/proc/self/fd");

    // Functional follow: open /dev/stdout for write and emit a marker.
    // open() must follow /dev/stdout -> /proc/self/fd/1 -> the console.
    int fd = open("/dev/stdout", O_WRONLY);
    if (fd < 0) {
        printf("dev_smoke: FAIL open(/dev/stdout) errno=%d\n", errno);
        fails++;
    } else {
        const char *m = "dev_smoke: /dev/stdout follow OK\n";
        if (write(fd, m, strlen(m)) < 0) {
            printf("dev_smoke: FAIL write(/dev/stdout) errno=%d\n", errno);
            fails++;
        }
        close(fd);
    }

    // /dev/kmsg write → readback: a message written to /dev/kmsg must land
    // in the kernel log ring (journald/early-systemd write here).
    int kf = open("/dev/kmsg", O_RDWR);
    if (kf < 0) {
        printf("dev_smoke: FAIL open(/dev/kmsg) errno=%d\n", errno);
        fails++;
    } else {
        const char *km = "<6>dev_smoke-kmsg-MARK42\n";
        write(kf, km, strlen(km));
        close(kf);
        int rf = open("/dev/kmsg", O_RDONLY);
        char ring[4096];
        int rn = rf >= 0 ? read(rf, ring, sizeof(ring) - 1) : -1;
        if (rf >= 0) close(rf);
        int found = 0;
        if (rn > 0) { ring[rn] = 0; found = strstr(ring, "dev_smoke-kmsg-MARK42") != 0; }
        if (!found) {
            printf("dev_smoke: FAIL /dev/kmsg write not in ring (rn=%d)\n", rn);
            fails++;
        } else {
            printf("dev_smoke: ok /dev/kmsg write injected into ring\n");
        }
    }

    if (fails == 0) { write(1, "dev_smoke: PASS\n", 16); return 0; }
    return 1;
}
