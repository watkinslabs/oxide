// /bin/sysbus_bind_probe - B589 sysfs bus driver-link and bind proof.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOOPS 2
#define RETRIES 50
#define SLEEP_US 100000

static const char *uart_drivers[] = { "8250-serial", "pl011-serial" };

static void emitf(const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n >= (int)sizeof buf) n = (int)sizeof buf - 1;
    write(1, buf, n);
    int fd = open("/dev/kmsg", O_WRONLY);
    if (fd >= 0) { write(fd, buf, n); close(fd); }
}

static void mount_api_fs(void) {
    mount("proc", "/proc", "proc", 0, "");
    mount("sysfs", "/sys", "sysfs", 0, "");
    mount("tmpfs", "/tmp", "tmpfs", 0, "");
    mount("devpts", "/dev/pts", "devpts", 0, "");
}

static int exists(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

static int read_link(const char *path, char *buf, size_t len, const char *tag) {
    ssize_t n = readlink(path, buf, len - 1);
    if (n < 0) {
        emitf("%s: FAIL readlink path=%s errno=%d\n", tag, path, errno);
        return 1;
    }
    buf[n] = '\0';
    return 0;
}

static const char *canon_tail(const char *target) {
    const char *p = strstr(target, "devices/");
    return p ? p : target;
}

static int dir_has(const char *path, const char *name) {
    DIR *d = opendir(path);
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, name)) { closedir(d); return 1; }
    }
    closedir(d);
    return 0;
}

static int write_token(const char *path, const char *token, const char *tag, int want_ok) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        emitf("%s: FAIL open path=%s errno=%d\n", tag, path, errno);
        return 1;
    }
    ssize_t n = write(fd, token, strlen(token));
    int saved = errno;
    close(fd);
    if (want_ok && n == (ssize_t)strlen(token)) return 0;
    if (!want_ok && n < 0) {
        emitf("%s: PASS errno=%d\n", tag, saved);
        return 0;
    }
    emitf("%s: FAIL n=%ld errno=%d\n", tag, (long)n, saved);
    return 1;
}

static int driver_entry_present(const char *driver, const char *dev) {
    char path[160];
    snprintf(path, sizeof path, "%s/%s", driver, dev);
    return exists(path);
}

static int wait_driver_entry(const char *driver, const char *dev, int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (driver_entry_present(driver, dev) == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int prove_link_pair(const char *bus, const char *driver_name, const char *dev, const char *tag) {
    char driver_dir[160], driver_link[192], bus_dev[192], dev_driver[256];
    char driver_target[256], bus_target[256], dev_driver_target[256];
    snprintf(driver_dir, sizeof driver_dir, "/sys/bus/%s/drivers/%s", bus, driver_name);
    snprintf(driver_link, sizeof driver_link, "%s/%s", driver_dir, dev);
    snprintf(bus_dev, sizeof bus_dev, "/sys/bus/%s/devices/%s", bus, dev);
    if (read_link(driver_link, driver_target, sizeof driver_target, tag)) return 1;
    if (read_link(bus_dev, bus_target, sizeof bus_target, tag)) return 1;
    if (strcmp(canon_tail(driver_target), canon_tail(bus_target))) {
        emitf("%s: FAIL driver_target=%s bus_target=%s\n", tag, driver_target, bus_target);
        return 1;
    }
    snprintf(dev_driver, sizeof dev_driver, "/sys/%s/driver", canon_tail(bus_target));
    if (read_link(dev_driver, dev_driver_target, sizeof dev_driver_target, tag)) return 1;
    if (!strstr(dev_driver_target, driver_dir + strlen("/sys"))) {
        emitf("%s: FAIL device_driver_target=%s want=%s\n", tag, dev_driver_target, driver_dir);
        return 1;
    }
    if (!dir_has(driver_dir, "bind") || !dir_has(driver_dir, "unbind") || !dir_has(driver_dir, dev)) {
        emitf("%s: FAIL driver_dir_entries driver=%s dev=%s\n", tag, driver_dir, dev);
        return 1;
    }
    emitf("%s: PASS bus=%s driver=%s dev=%s target=%s\n", tag, bus, driver_name, dev, driver_target);
    return 0;
}

static int first_bound_dev(const char *driver_dir, char *out, size_t len) {
    DIR *d = opendir(driver_dir);
    if (!d) return 1;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.' || !strcmp(e->d_name, "bind") || !strcmp(e->d_name, "unbind")) continue;
        snprintf(out, len, "%s", e->d_name);
        closedir(d);
        return 0;
    }
    closedir(d);
    return 1;
}

static const char *active_uart_driver(void) {
    static char path[160];
    for (size_t i = 0; i < sizeof uart_drivers / sizeof uart_drivers[0]; i++) {
        snprintf(path, sizeof path, "/sys/bus/platform/drivers/%s/serial0", uart_drivers[i]);
        if (exists(path)) return uart_drivers[i];
    }
    return NULL;
}

static int prove_static_bus(const char *bus, const char *driver, const char *tag) {
    char dir[160], dev[80];
    snprintf(dir, sizeof dir, "/sys/bus/%s/drivers/%s", bus, driver);
    if (first_bound_dev(dir, dev, sizeof dev)) {
        emitf("%s: FAIL no bound device in %s\n", tag, dir);
        return 1;
    }
    return prove_link_pair(bus, driver, dev, tag);
}

static int prove_platform_bind_unbind(const char *driver) {
    char dir[160], bind[192], unbind[192];
    snprintf(dir, sizeof dir, "/sys/bus/platform/drivers/%s", driver);
    snprintf(bind, sizeof bind, "%s/bind", dir);
    snprintf(unbind, sizeof unbind, "%s/unbind", dir);
    if (prove_link_pair("platform", driver, "serial0", "b589_platform_link_initial")) return 1;
    if (write_token(bind, "serial0", "b589_platform_duplicate_bind", 0)) return 1;
    for (int loop = 1; loop <= LOOPS; loop++) {
        if (write_token(unbind, "serial0", "b589_platform_unbind_write", 1)) return 1;
        if (wait_driver_entry(dir, "serial0", 0) || exists("/sys/devices/platform/serial0/driver")) {
            emitf("b589_platform_unbound_links: FAIL loop=%d\n", loop);
            return 1;
        }
        if (dir_has(dir, "serial0")) {
            emitf("b589_platform_driver_readdir_absent: FAIL loop=%d\n", loop);
            return 1;
        }
        emitf("b589_platform_unbound_links: PASS loop=%d\n", loop);
        if (write_token(bind, "serial0", "b589_platform_bind_write", 1)) return 1;
        if (wait_driver_entry(dir, "serial0", 1)) {
            emitf("b589_platform_rebound_links: FAIL loop=%d\n", loop);
            return 1;
        }
        if (prove_link_pair("platform", driver, "serial0", "b589_platform_link_rebound")) return 1;
        emitf("b589_platform_bind_loop: PASS loop=%d driver=%s\n", loop, driver);
    }
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mount_api_fs();
    emitf("sysbus_bind_probe: START\n");
    const char *driver = active_uart_driver();
    if (!driver) {
        emitf("b589_platform_active_driver: FAIL no serial0 driver\n");
        return 1;
    }
    emitf("b589_platform_active_driver: PASS driver=%s\n", driver);
    if (prove_platform_bind_unbind(driver)) return 1;
    if (prove_static_bus("virtio", "virtio-blk", "b589_virtio_driver_link")) return 1;
    if (prove_static_bus("pci", "virtio-pci", "b589_pci_driver_link")) return 1;
    emitf("sysbus_bind_probe: PASS\n");
    emitf("driver_path_smoke: PASS - sysbus-bind\n");
    return 0;
}
