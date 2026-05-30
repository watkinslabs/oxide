// /bin/cgroup_smoke — K1 cgroup v2 unified-hierarchy acceptance.
// Exercises the real interface end-to-end via direct syscalls (no
// shell, no PATH, no command-substitution fragility):
//   1. read /sys/fs/cgroup/cgroup.controllers — must list pids+memory
//   2. enable them in cgroup.subtree_control
//   3. mkdir a child cgroup
//   4. write pids.max=7, read it back == 7
//   5. move self into child via cgroup.procs; /proc/self/cgroup tracks
//   6. move self back to root; rmdir the (now-empty) child
// Prints "cgroup_smoke: PASS" only if every step holds.

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#define ROOT "/sys/fs/cgroup"
#define CG   ROOT "/cg_smoke"

static int fail(const char *why) {
    char b[96]; int n = snprintf(b, sizeof b, "cgroup_smoke: FAIL %s errno=%d\n", why, errno);
    write(1, b, n);
    return 1;
}

// Read a file fully into buf; returns byte count or -1.
static int slurp(const char *path, char *buf, int cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int total = 0, r;
    while (total < cap - 1 && (r = read(fd, buf + total, cap - 1 - total)) > 0)
        total += r;
    close(fd);
    buf[total > 0 ? total : 0] = '\0';
    return total;
}

// Write a string to a file in one write(); returns 0 / -1.
static int put(const char *path, const char *val) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int len = (int)strlen(val);
    int w = write(fd, val, len);
    close(fd);
    return (w == len) ? 0 : -1;
}

int main(void) {
    char buf[256];

    // 1. controllers list must advertise pids + memory.
    if (slurp(ROOT "/cgroup.controllers", buf, sizeof buf) <= 0) return fail("read-controllers");
    if (!strstr(buf, "pids"))   return fail("no-pids-controller");
    if (!strstr(buf, "memory")) return fail("no-memory-controller");

    // 2. delegate pids+memory to children.
    if (put(ROOT "/cgroup.subtree_control", "+pids +memory") < 0) return fail("subtree_control");

    // 3. create a child cgroup (idempotent across reboots).
    rmdir(CG);
    if (mkdir(CG, 0755) < 0) return fail("mkdir");

    // 4. set + read back pids.max.
    if (put(CG "/pids.max", "7") < 0) return fail("write-pids.max");
    if (slurp(CG "/pids.max", buf, sizeof buf) <= 0) return fail("read-pids.max");
    if (atoi(buf) != 7) return fail("pids.max-mismatch");

    // 5. move self in; /proc/self/cgroup must report the child path.
    char pid[16]; snprintf(pid, sizeof pid, "%d", (int)getpid());
    if (put(CG "/cgroup.procs", pid) < 0) return fail("attach");
    if (slurp("/proc/self/cgroup", buf, sizeof buf) <= 0) return fail("read-self-cgroup");
    if (!strstr(buf, "/cg_smoke")) return fail("self-cgroup-path");

    // 6. move back to root, then the child is empty and removable.
    if (put(ROOT "/cgroup.procs", pid) < 0) return fail("detach");
    if (rmdir(CG) < 0) return fail("rmdir");

    write(1, "cgroup_smoke: PASS\n", 19);
    return 0;
}
