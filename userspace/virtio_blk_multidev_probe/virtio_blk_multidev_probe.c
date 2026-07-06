// /bin/virtio_blk_multidev_probe — B581 repeated virtio-blk rebind proof.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_DEVS 12
#define MAX_NAME 64
#define MAX_PATH 160
#define RETRIES 50
#define SLEEP_US 100000
#define REBIND_LOOPS 3

static const char *driver = "/sys/bus/virtio/drivers/virtio-blk";
static const char *scratch_serial = "oxide-scratch";

static void emit_line(const char *msg) {
    write(1, msg, strlen(msg));
    int fd = open("/dev/kmsg", O_WRONLY);
    if (fd >= 0) {
        write(fd, msg, strlen(msg));
        close(fd);
    }
}

static void mount_api_fs(void) {
    mount("proc", "/proc", "proc", 0, "");
    mount("sysfs", "/sys", "sysfs", 0, "");
    mount("tmpfs", "/tmp", "tmpfs", 0, "");
    mount("devpts", "/dev/pts", "devpts", 0, "");
}

static void emit_status(const char *tag, int loop) {
    char buf[96];
    int n = snprintf(buf, sizeof buf, "%s loop=%d\n", tag, loop);
    if (n > 0) emit_line(buf);
}

static void emit_count(const char *tag, int value) {
    char buf[96];
    int n = snprintf(buf, sizeof buf, "%s count=%d\n", tag, value);
    if (n > 0) emit_line(buf);
}

static void emit_fail_count(const char *tag, int loop, int value) {
    char buf[128];
    int n = snprintf(buf, sizeof buf, "%s: FAIL loop=%d count=%d\n", tag, loop, value);
    if (n > 0) emit_line(buf);
}

static void emit_fail_name(const char *tag, int loop, const char *name) {
    char buf[128];
    int n = snprintf(buf, sizeof buf, "%s: FAIL loop=%d name=%s\n", tag, loop, name);
    if (n > 0) emit_line(buf);
}

static int list_bound(char names[MAX_DEVS][MAX_NAME]) {
    DIR *d = opendir(driver);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (!strcmp(e->d_name, "bind") || !strcmp(e->d_name, "unbind")) continue;
        if (n < MAX_DEVS) {
            strncpy(names[n], e->d_name, MAX_NAME - 1);
            names[n][MAX_NAME - 1] = '\0';
        }
        n++;
    }
    closedir(d);
    return n;
}

static int device_bound(const char *dev) {
    char names[MAX_DEVS][MAX_NAME];
    int n = list_bound(names);
    if (n < 0) return 0;
    for (int i = 0; i < n && i < MAX_DEVS; i++) {
        if (!strcmp(names[i], dev)) return 1;
    }
    return 0;
}

static int wait_bound(const char *dev, int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (device_bound(dev) == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int write_token(const char *leaf, const char *token, const char *tag) {
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s/%s", driver, leaf);
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        char msg[128];
        snprintf(msg, sizeof msg, "%s: FAIL open errno=%d token=%s\n", tag, errno, token);
        emit_line(msg);
        return 1;
    }
    ssize_t n = write(fd, token, strlen(token));
    int saved = errno;
    close(fd);
    if (n != (ssize_t)strlen(token)) {
        char msg[128];
        snprintf(msg, sizeof msg, "%s: FAIL write n=%ld errno=%d token=%s\n", tag, (long)n, saved, token);
        emit_line(msg);
        return 1;
    }
    char msg[64];
    snprintf(msg, sizeof msg, "%s: PASS\n", tag);
    emit_line(msg);
    return 0;
}

static int count_vd(void) {
    DIR *d = opendir("/sys/block");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strncmp(e->d_name, "vd", 2)) n++;
    }
    closedir(d);
    return n;
}

static int wait_vd_count_exact(int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (count_vd() == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int read_attr(const char *path, char *buf, size_t len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, len - 1);
    int saved = errno;
    close(fd);
    if (n < 0) { errno = saved; return -1; }
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' ')) {
        buf[n - 1] = '\0';
        n--;
    }
    return 0;
}

static int find_disk_by_serial(const char *serial, char *name, size_t len) {
    DIR *d = opendir("/sys/block");
    if (!d) return -1;
    int found = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "vd", 2)) continue;
        char path[MAX_PATH], buf[MAX_NAME];
        snprintf(path, sizeof path, "/sys/block/%s/device/serial", e->d_name);
        if (!read_attr(path, buf, sizeof buf) && !strcmp(buf, serial)) {
            strncpy(name, e->d_name, len - 1);
            name[len - 1] = '\0';
            found = 1;
            break;
        }
    }
    closedir(d);
    return found ? 0 : 1;
}

static int wait_disk_serial(int want_present, char *name, size_t len) {
    for (int i = 0; i < RETRIES; i++) {
        int present = find_disk_by_serial(scratch_serial, name, len) == 0;
        if (present == want_present) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int readable(const char *path, const char *tag, int loop) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { emit_fail_name(tag, loop, path); return 1; }
    char buf[64];
    ssize_t n = read(fd, buf, sizeof buf);
    close(fd);
    if (n <= 0) { emit_fail_name(tag, loop, path); return 1; }
    return 0;
}

static int stale_path_visible(const char *name) {
    char path[MAX_PATH];
    snprintf(path, sizeof path, "/sys/block/%s/size", name);
    if (access(path, R_OK) == 0) return 1;
    snprintf(path, sizeof path, "/dev/%s", name);
    if (access(path, F_OK) == 0) return 1;
    return 0;
}

static int prove_disk_attrs(const char *name, int loop) {
    char path[MAX_PATH];
    snprintf(path, sizeof path, "/sys/block/%s/size", name);
    if (readable(path, "b581_blk_size_read", loop)) return 1;
    snprintf(path, sizeof path, "/sys/block/%s/dev", name);
    if (readable(path, "b581_blk_dev_read", loop)) return 1;
    snprintf(path, sizeof path, "/sys/block/%s/queue/logical_block_size", name);
    if (readable(path, "b581_blk_lbs_read", loop)) return 1;
    snprintf(path, sizeof path, "/sys/block/%s/device/serial", name);
    if (readable(path, "b581_blk_serial_read", loop)) return 1;
    snprintf(path, sizeof path, "/dev/%s", name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { emit_fail_name("b581_blk_devnode_open", loop, path); return 1; }
    close(fd);
    return 0;
}

static int run_probe(const char *path) {
    int pid = fork();
    if (pid == 0) {
        char *const argv[] = {(char *)path, NULL};
        execv(path, argv);
        _exit(127);
    }
    int st = 0;
    if (pid < 0) return 1;
    if (waitpid(pid, &st, 0) < 0) return 1;
    return st != 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    emit_line("virtio_blk_multidev_probe: START\n");
    mount_api_fs();

    char bound[MAX_DEVS][MAX_NAME];
    int bound_n = list_bound(bound);
    emit_count("b581_bound_devices_seen", bound_n);
    if (bound_n < 3) { emit_line("b581_bound_devices: FAIL count<3\n"); return 1; }
    const char *dev = bound[bound_n - 1];

    char disk[MAX_NAME];
    if (find_disk_by_serial(scratch_serial, disk, sizeof disk)) {
        emit_line("b581_scratch_serial_initial: FAIL\n");
        return 1;
    }
    emit_count("b581_initial_vd_seen", count_vd());
    if (prove_disk_attrs(disk, 0)) return 1;

    int baseline = count_vd();
    for (int loop = 1; loop <= REBIND_LOOPS; loop++) {
        char before[MAX_NAME];
        strncpy(before, disk, sizeof before - 1);
        before[sizeof before - 1] = '\0';

        char msg[128];
        snprintf(msg, sizeof msg, "b581_unbind_dev loop=%d dev=%s disk=%s\n", loop, dev, before);
        emit_line(msg);
        if (write_token("unbind", dev, "b581_unbind_write")) return 1;
        if (wait_bound(dev, 0)) { emit_status("b581_virtio_blk_unbind: FAIL", loop); return 1; }
        if (wait_vd_count_exact(baseline - 1)) { emit_fail_count("b581_blk_remove_count", loop, count_vd()); return 1; }
        if (wait_disk_serial(0, disk, sizeof disk)) { emit_status("b581_blk_remove_serial: FAIL", loop); return 1; }
        if (stale_path_visible(before)) { emit_fail_name("b581_blk_remove_path", loop, before); return 1; }
        emit_status("b581_virtio_blk_unbind: PASS", loop);

        if (write_token("bind", dev, "b581_bind_write")) return 1;
        if (wait_bound(dev, 1)) { emit_status("b581_virtio_blk_rebind: FAIL", loop); return 1; }
        if (wait_vd_count_exact(baseline)) { emit_fail_count("b581_blk_readd_count", loop, count_vd()); return 1; }
        if (wait_disk_serial(1, disk, sizeof disk)) { emit_status("b581_blk_readd_serial: FAIL", loop); return 1; }
        if (prove_disk_attrs(disk, loop)) return 1;
        emit_status("b581_virtio_blk_rebind: PASS", loop);
    }

    if (run_probe("/bin/sysblock_probe")) return 1;
    emit_line("driver_path_smoke: PASS - block virtio-blk-multidev-rebind\n");
    return 0;
}
