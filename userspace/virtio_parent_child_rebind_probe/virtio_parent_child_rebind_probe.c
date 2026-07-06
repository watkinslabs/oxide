// /bin/virtio_parent_child_rebind_probe - virtio-pci parent/child rebind proof.
// Boots with two virtio-rng PCI parents, unbinds one parent, proves its child
// disappears, then rebinds the parent and proves virtio-rng service returns.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_DEVS 16
#define MAX_NAME 64
#define MAX_PATH 192
#define RETRIES 60
#define SLEEP_US 100000
#define REBIND_LOOPS 3

static const char *pci_driver = "/sys/bus/pci/drivers/virtio-pci";
static const char *rng_driver = "/sys/bus/virtio/drivers/virtio-rng";

static void emit_line(const char *msg) {
    write(1, msg, strlen(msg));
    int fd = open("/dev/kmsg", O_WRONLY);
    if (fd >= 0) {
        write(fd, msg, strlen(msg));
        close(fd);
    }
}

static void emitf(const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof buf) n = sizeof buf - 1;
    write(1, buf, n);
    int fd = open("/dev/kmsg", O_WRONLY);
    if (fd >= 0) {
        write(fd, buf, n);
        close(fd);
    }
}

static void mount_api_fs(void) {
    mount("proc", "/proc", "proc", 0, "");
    mount("sysfs", "/sys", "sysfs", 0, "");
    mount("tmpfs", "/tmp", "tmpfs", 0, "");
    mount("devpts", "/dev/pts", "devpts", 0, "");
}

static int path_lexists(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

static int read_file(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, cap - 1);
    int saved = errno;
    close(fd);
    if (n < 0) { errno = saved; return -1; }
    buf[n] = '\0';
    return 0;
}

static int write_token(const char *dir, const char *leaf, const char *token, const char *tag) {
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s/%s", dir, leaf);
    int fd = open(path, O_WRONLY);
    if (fd < 0) { emitf("%s: FAIL open errno=%d\n", tag, errno); return 1; }
    ssize_t n = write(fd, token, strlen(token));
    int saved = errno;
    close(fd);
    if (n != (ssize_t)strlen(token)) {
        emitf("%s: FAIL write n=%ld errno=%d\n", tag, (long)n, saved);
        return 1;
    }
    emitf("%s: PASS\n", tag);
    return 0;
}

static int list_bound(const char *driver, char names[MAX_DEVS][MAX_NAME]) {
    DIR *d = opendir(driver);
    if (!d) { emitf("b583_list_bound: FAIL %s errno=%d\n", driver, errno); return -1; }
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

static int count_bound(const char *driver) {
    char names[MAX_DEVS][MAX_NAME];
    return list_bound(driver, names);
}

static int read_hwrng(const char *tag) {
    int fd = open("/dev/hwrng", O_RDONLY);
    if (fd < 0) { emitf("%s: FAIL open errno=%d\n", tag, errno); return 1; }
    unsigned char buf[32];
    ssize_t n = read(fd, buf, sizeof buf);
    int saved = errno;
    close(fd);
    if (n <= 0) { emitf("%s: FAIL read n=%ld errno=%d\n", tag, (long)n, saved); return 1; }
    emitf("%s: PASS n=%ld\n", tag, (long)n);
    return 0;
}

static int wait_count(const char *driver, int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (count_bound(driver) == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int find_rng_parent(char *out, size_t cap) {
    char names[MAX_DEVS][MAX_NAME];
    int n = list_bound(pci_driver, names);
    if (n < 0) return 1;
    for (int i = 0; i < n && i < MAX_DEVS; i++) {
        char path[MAX_PATH], body[32];
        snprintf(path, sizeof path, "/sys/bus/pci/devices/%s/device", names[i]);
        if (read_file(path, body, sizeof body) == 0 && strstr(body, "0x1044")) {
            strncpy(out, names[i], cap - 1);
            out[cap - 1] = '\0';
            emitf("b583_rng_parent: PASS %s\n", out);
            return 0;
        }
    }
    emitf("b583_rng_parent: FAIL no bound virtio-rng PCI parent\n");
    return 1;
}

static int missing_child(char before[MAX_DEVS][MAX_NAME], int before_n, char *out, size_t cap) {
    char after[MAX_DEVS][MAX_NAME];
    int after_n = list_bound(rng_driver, after);
    if (after_n < 0) return 1;
    for (int i = 0; i < before_n && i < MAX_DEVS; i++) {
        int found = 0;
        for (int j = 0; j < after_n && j < MAX_DEVS; j++) {
            if (!strcmp(before[i], after[j])) found = 1;
        }
        if (!found) {
            strncpy(out, before[i], cap - 1);
            out[cap - 1] = '\0';
            return 0;
        }
    }
    emitf("b583_missing_child: FAIL no child disappeared\n");
    return 1;
}

static int require_absent(const char *path, const char *tag, int loop) {
    if (path_lexists(path)) {
        emitf("%s: FAIL loop=%d stale %s\n", tag, loop, path);
        return 1;
    }
    emitf("%s: PASS loop=%d absent %s\n", tag, loop, path);
    return 0;
}

static int exercise_parent(const char *parent) {
    for (int loop = 1; loop <= REBIND_LOOPS; loop++) {
        char before[MAX_DEVS][MAX_NAME], child[MAX_NAME], path[MAX_PATH];
        int before_n = list_bound(rng_driver, before);
        if (before_n < 2) { emitf("b583_rng_children: FAIL loop=%d count=%d\n", loop, before_n); return 1; }
        if (read_hwrng("b583_hwrng_before")) return 1;
        emitf("b583_unbind_parent_%d: %s\n", loop, parent);
        if (write_token(pci_driver, "unbind", parent, "b583_parent_unbind_write")) return 1;
        if (wait_count(rng_driver, before_n - 1)) {
            emitf("b583_rng_count_after_parent_unbind: FAIL loop=%d count=%d want=%d\n",
                   loop, count_bound(rng_driver), before_n - 1);
            return 1;
        }
        if (missing_child(before, before_n, child, sizeof child)) return 1;
        snprintf(path, sizeof path, "/sys/bus/virtio/devices/%s", child);
        if (require_absent(path, "b583_child_bus_absent", loop)) return 1;
        snprintf(path, sizeof path, "/sys/devices/virtio/%s", child);
        if (require_absent(path, "b583_child_dev_absent", loop)) return 1;
        snprintf(path, sizeof path, "%s/%s", pci_driver, parent);
        if (require_absent(path, "b583_parent_driver_absent", loop)) return 1;
        if (read_hwrng("b583_hwrng_after_unbind")) return 1;
        if (write_token(pci_driver, "bind", parent, "b583_parent_bind_write")) return 1;
        if (wait_count(rng_driver, before_n)) {
            emitf("b583_rng_count_after_parent_rebind: FAIL loop=%d count=%d want=%d\n",
                   loop, count_bound(rng_driver), before_n);
            return 1;
        }
        if (read_hwrng("b583_hwrng_after_rebind")) return 1;
        emitf("b583_parent_child_rebind: PASS loop=%d parent=%s old_child=%s\n",
               loop, parent, child);
    }
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    emit_line("virtio_parent_child_rebind_probe: START\n");
    mount_api_fs();
    char parent[MAX_NAME];
    if (find_rng_parent(parent, sizeof parent)) return 1;
    if (exercise_parent(parent)) return 1;
    emit_line("driver_path_smoke: PASS - virtio-parent-child-rebind\n");
    return 0;
}
