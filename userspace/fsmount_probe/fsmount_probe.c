// /bin/fsmount_probe — exercises the new mount API (K6): the
// fsopen → fsconfig → fsmount → move_mount flow systemd 254+ uses to
// mount filesystems. Mounts a fresh tmpfs at /run/k6mnt and verifies a
// file written through the new mount reads back. Prints PASS/FAIL to the
// console (captured on the boot serial).

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#ifndef __NR_fsopen
#define __NR_fsopen        430
#define __NR_fsconfig      431
#define __NR_fsmount       432
#define __NR_move_mount    429
#endif
#define __NR_open_tree_    428
#define __NR_mount_setattr_ 442

#define FSCONFIG_CMD_CREATE      6
#define MOVE_MOUNT_F_EMPTY_PATH  0x00000004
#define OPEN_TREE_CLONE          1
#define MS_SHARED                (1u << 20)
#define AT_FDCWD_                (-100)

struct mount_attr_ {
    unsigned long long attr_set, attr_clr, propagation, userns_fd;
};

int main(void) {
    // fsopen("tmpfs") → fs_context fd.
    long fsfd = syscall(__NR_fsopen, "tmpfs", 0);
    if (fsfd < 0) { printf("fsmount_probe: FAIL fsopen errno=%d\n", errno); return 1; }

    // fsconfig(CMD_CREATE) finalises the context.
    if (syscall(__NR_fsconfig, (int)fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0) {
        printf("fsmount_probe: FAIL fsconfig errno=%d\n", errno); return 1;
    }

    // fsmount → detached mount object fd.
    long mfd = syscall(__NR_fsmount, (int)fsfd, 0, 0);
    if (mfd < 0) { printf("fsmount_probe: FAIL fsmount errno=%d\n", errno); return 1; }

    // The mountpoint must exist; /run is tmpfs.
    mkdir("/run/k6mnt", 0755);

    // move_mount attaches the detached mount at /run/k6mnt.
    if (syscall(__NR_move_mount, (int)mfd, "", AT_FDCWD_, "/run/k6mnt",
                MOVE_MOUNT_F_EMPTY_PATH) < 0) {
        printf("fsmount_probe: FAIL move_mount errno=%d\n", errno); return 1;
    }

    // Verify: write+read a file through the freshly-mounted tmpfs.
    int fd = open("/run/k6mnt/hello", O_CREAT | O_RDWR, 0644);
    if (fd < 0) { printf("fsmount_probe: FAIL open errno=%d\n", errno); return 1; }
    if (write(fd, "K6OK", 4) != 4) { printf("fsmount_probe: FAIL write errno=%d\n", errno); return 1; }
    lseek(fd, 0, SEEK_SET);
    char buf[8] = {0};
    int n = read(fd, buf, 4);
    close(fd);
    if (n != 4 || memcmp(buf, "K6OK", 4) != 0) {
        printf("fsmount_probe: FAIL readback n=%d '%s'\n", n, buf); return 1;
    }

    // open_tree(OPEN_TREE_CLONE) → detached clone → move_mount to a 2nd
    // point; the same file is visible through the clone.
    long otfd = syscall(__NR_open_tree_, AT_FDCWD_, "/run/k6mnt", OPEN_TREE_CLONE);
    if (otfd < 0) { printf("fsmount_probe: FAIL open_tree errno=%d\n", errno); return 1; }
    mkdir("/run/k6mnt2", 0755);
    if (syscall(__NR_move_mount, (int)otfd, "", AT_FDCWD_, "/run/k6mnt2",
                MOVE_MOUNT_F_EMPTY_PATH) < 0) {
        printf("fsmount_probe: FAIL move_mount(clone) errno=%d\n", errno); return 1;
    }
    int fd2 = open("/run/k6mnt2/hello", O_RDONLY);
    if (fd2 < 0) { printf("fsmount_probe: FAIL open(clone) errno=%d\n", errno); return 1; }
    char b2[8] = {0};
    int n2 = read(fd2, b2, 4);
    close(fd2);
    if (n2 != 4 || memcmp(b2, "K6OK", 4) != 0) {
        printf("fsmount_probe: FAIL clone readback n=%d '%s'\n", n2, b2); return 1;
    }

    // mount_setattr → make /run/k6mnt shared.
    struct mount_attr_ ma = {0};
    ma.propagation = MS_SHARED;
    if (syscall(__NR_mount_setattr_, AT_FDCWD_, "/run/k6mnt", 0, &ma, sizeof ma) < 0) {
        printf("fsmount_probe: FAIL mount_setattr errno=%d\n", errno); return 1;
    }

    printf("fsmount_probe: PASS new-mount-api tmpfs + open_tree clone + mount_setattr\n");
    return 0;
}
