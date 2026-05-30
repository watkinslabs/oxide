// /bin/statfs_smoke — statfs(2)/fstatfs(2) f_type magic acceptance.
// systemd & util-linux detect filesystem type from statfs f_type
// (cg_all_unified, path_is_fs_type, mountpoint probes). A constant/
// wrong magic made cgroup2 / tmpfs / proc detection fail. This checks
// each well-known mount reports its real linux/magic.h s_magic, and
// that fstatfs on an open fd agrees with statfs on the path.

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/vfs.h>

#define PROC_MAGIC    0x9fa0
#define SYSFS_MAGIC   0x62656572
#define TMPFS_MAGIC   0x01021994
#define CGROUP2_MAGIC 0x63677270
#define EXT4_MAGIC    0xEF53

static int fails = 0;

static void check(const char *path, unsigned long want) {
    struct statfs s;
    if (statfs(path, &s) != 0) {
        printf("statfs_smoke: FAIL statfs(%s) errno=%d\n", path, errno);
        fails++;
        return;
    }
    unsigned long got = (unsigned long)s.f_type;
    if (got != want) {
        printf("statfs_smoke: FAIL %s f_type=0x%lx want=0x%lx\n", path, got, want);
        fails++;
    } else {
        printf("statfs_smoke: ok %s f_type=0x%lx\n", path, got);
    }
    // f_namelen must be NAME_MAX (255), not 0 — was written at the
    // wrong struct offset before this fix.
    if (s.f_namelen != 255) {
        printf("statfs_smoke: FAIL %s f_namelen=%ld want=255\n", path, (long)s.f_namelen);
        fails++;
    }
}

int main(void) {
    check("/proc",          PROC_MAGIC);
    check("/sys",           SYSFS_MAGIC);
    check("/sys/fs/cgroup", CGROUP2_MAGIC);
    check("/",              EXT4_MAGIC);
    check("/tmp",           TMPFS_MAGIC);
    check("/dev",           TMPFS_MAGIC);

    // fstatfs on a cgroup dir fd must agree with statfs on the path —
    // this is the path systemd uses (open the hierarchy, fstatfs it).
    int fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        printf("statfs_smoke: FAIL open(/sys/fs/cgroup) errno=%d\n", errno);
        fails++;
    } else {
        struct statfs s;
        if (fstatfs(fd, &s) != 0) {
            printf("statfs_smoke: FAIL fstatfs errno=%d\n", errno);
            fails++;
        } else if ((unsigned long)s.f_type != CGROUP2_MAGIC) {
            printf("statfs_smoke: FAIL fstatfs f_type=0x%lx want=0x%x\n",
                   (unsigned long)s.f_type, CGROUP2_MAGIC);
            fails++;
        } else {
            printf("statfs_smoke: ok fstatfs(/sys/fs/cgroup) f_type=0x%lx\n",
                   (unsigned long)s.f_type);
        }
        close(fd);
    }

    if (fails == 0) {
        write(1, "statfs_smoke: PASS\n", 19);
        return 0;
    }
    return 1;
}
