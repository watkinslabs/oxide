// /bin/uart_rebind_probe - platform UART live sysfs rebind proof.
// Runs against platform/serial0 with the active per-arch driver:
// 8250-serial on x86_64, pl011-serial on aarch64.

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOOPS 3
#define RETRIES 50
#define SLEEP_US 100000

static const char *drivers[] = { "8250-serial", "pl011-serial" };
static const char *dev = "serial0";

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

static void driver_path(char *buf, size_t len, const char *driver, const char *leaf) {
    snprintf(buf, len, "/sys/bus/platform/drivers/%s/%s", driver, leaf);
}

static int lstat_path(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

static int link_present(const char *driver) {
    char path[128];
    driver_path(path, sizeof path, driver, dev);
    return lstat_path(path);
}

static int starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static const char *active_driver(void) {
    for (size_t i = 0; i < sizeof drivers / sizeof drivers[0]; i++) {
        if (link_present(drivers[i])) return drivers[i];
    }
    return NULL;
}

static int prove_uart_singleton(const char *driver) {
    DIR *d = opendir("/sys/bus/platform/devices");
    if (!d) {
        emitf("b590_uart_singleton_device: FAIL opendir errno=%d\n", errno);
        return 1;
    }
    int serial_count = 0;
    int serial0_seen = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (!starts_with(de->d_name, "serial")) continue;
        serial_count++;
        if (strcmp(de->d_name, "serial0") == 0) {
            serial0_seen = 1;
        } else {
            emitf("b590_uart_singleton_device: FAIL unexpected=%s\n", de->d_name);
        }
    }
    closedir(d);
    if (serial_count != 1 || !serial0_seen) {
        emitf("b590_uart_singleton_device: FAIL count=%d serial0=%d\n",
              serial_count, serial0_seen);
        return 1;
    }

    int driver_dirs = 0;
    for (size_t i = 0; i < sizeof drivers / sizeof drivers[0]; i++) {
        char path[128];
        driver_path(path, sizeof path, drivers[i], "");
        size_t n = strlen(path);
        if (n > 0 && path[n - 1] == '/') path[n - 1] = '\0';
        if (lstat_path(path)) driver_dirs++;
    }
    if (driver_dirs != 1) {
        emitf("b590_uart_singleton_driver: FAIL count=%d active=%s\n",
              driver_dirs, driver);
        return 1;
    }
    emitf("b590_uart_singleton_device: PASS device=serial0 count=%d\n", serial_count);
    emitf("b590_uart_singleton_driver: PASS driver=%s count=%d\n", driver, driver_dirs);
    return 0;
}

static int writable_attr(const char *driver, const char *leaf, const char *tag) {
    char path[128];
    driver_path(path, sizeof path, driver, leaf);
    if (access(path, W_OK) == 0) return 0;
    emitf("%s: FAIL path=%s errno=%d\n", tag, path, errno);
    return 1;
}

static int write_attr_quiet(const char *driver, const char *leaf, const char *tag) {
    char path[128];
    driver_path(path, sizeof path, driver, leaf);
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        emitf("%s: FAIL open path=%s errno=%d\n", tag, path, errno);
        return 1;
    }
    ssize_t n = write(fd, dev, strlen(dev));
    int saved = errno;
    close(fd);
    if (n != (ssize_t)strlen(dev)) {
        emitf("%s: FAIL write n=%ld errno=%d\n", tag, (long)n, saved);
        return 1;
    }
    return 0;
}

static int wait_link(const char *driver, int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (link_present(driver) == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int readlink_has(const char *path, const char *needle, const char *tag) {
    char buf[256];
    ssize_t n = readlink(path, buf, sizeof buf - 1);
    if (n < 0) {
        emitf("%s: FAIL readlink errno=%d\n", tag, errno);
        return 1;
    }
    buf[n] = '\0';
    if (!strstr(buf, needle)) {
        emitf("%s: FAIL target=%s needle=%s\n", tag, buf, needle);
        return 1;
    }
    emitf("%s: PASS target=%s\n", tag, buf);
    return 0;
}

static int prove_bound_links(const char *driver, int loop) {
    char driver_dev[128];
    driver_path(driver_dev, sizeof driver_dev, driver, dev);
    if (!lstat_path(driver_dev)) {
        emitf("b585_driver_link_present: FAIL loop=%d driver=%s\n", loop, driver);
        return 1;
    }
    if (readlink_has(driver_dev, "/devices/platform/serial0", "b585_driver_link_target")) return 1;
    if (readlink_has("/sys/devices/platform/serial0/driver",
                     "/bus/platform/drivers/", "b585_device_driver_link")) return 1;
    return 0;
}

static int prove_unbound_links(const char *driver, int loop) {
    char driver_dev[128];
    driver_path(driver_dev, sizeof driver_dev, driver, dev);
    if (lstat_path(driver_dev)) {
        emitf("b585_driver_link_absent: FAIL loop=%d driver=%s\n", loop, driver);
        return 1;
    }
    if (lstat_path("/sys/devices/platform/serial0/driver")) {
        emitf("b585_device_driver_absent: FAIL loop=%d driver=%s\n", loop, driver);
        return 1;
    }
    return 0;
}

static int tty_write_probe(int loop) {
    int fd = open("/dev/ttyS0", O_WRONLY);
    if (fd < 0) {
        emitf("b585_ttyS0_open: FAIL loop=%d errno=%d\n", loop, errno);
        return 1;
    }
    char buf[96];
    int n = snprintf(buf, sizeof buf, "b585_ttyS0_write: PASS loop=%d\n", loop);
    ssize_t wr = write(fd, buf, n);
    int saved = errno;
    close(fd);
    if (wr != n) {
        emitf("b585_ttyS0_write: FAIL loop=%d n=%ld errno=%d\n", loop, (long)wr, saved);
        return 1;
    }
    emitf("b585_ttyS0_write_confirmed: PASS loop=%d\n", loop);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mount_api_fs();
    emitf("uart_rebind_probe: START\n");

    const char *driver = active_driver();
    if (!driver) {
        emitf("b585_active_uart_driver: FAIL no serial0 driver link\n");
        return 1;
    }
    emitf("b585_active_uart_driver: PASS driver=%s\n", driver);
    if (prove_uart_singleton(driver)) return 1;
    if (writable_attr(driver, "bind", "b585_bind_attr") ||
        writable_attr(driver, "unbind", "b585_unbind_attr") ||
        prove_bound_links(driver, 0) ||
        tty_write_probe(0)) return 1;

    for (int loop = 1; loop <= LOOPS; loop++) {
        emitf("b585_uart_rebind_loop: START loop=%d driver=%s dev=%s\n", loop, driver, dev);
        if (write_attr_quiet(driver, "unbind", "b585_unbind_write")) return 1;
        if (wait_link(driver, 0)) {
            emitf("b585_driver_link_absent: FAIL timeout loop=%d driver=%s\n", loop, driver);
            return 1;
        }
        if (prove_unbound_links(driver, loop)) return 1;
        if (write_attr_quiet(driver, "bind", "b585_bind_write")) return 1;
        if (wait_link(driver, 1)) {
            emitf("b585_driver_link_restored: FAIL timeout loop=%d driver=%s\n", loop, driver);
            return 1;
        }
        emitf("b585_driver_link_absent: PASS loop=%d driver=%s\n", loop, driver);
        emitf("b585_device_driver_absent: PASS loop=%d driver=%s\n", loop, driver);
        if (prove_bound_links(driver, loop) || tty_write_probe(loop)) return 1;
        emitf("b585_uart_rebind_loop: PASS loop=%d driver=%s dev=%s\n", loop, driver, dev);
    }

    emitf("driver_path_smoke: PASS - uart-rebind\n");
    return 0;
}
