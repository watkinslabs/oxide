// /bin/ps2_rebind_probe - platform i8042 live sysfs rebind proof.
// x86_64 must expose platform/i8042 bound to i8042-kbd. aarch64 QEMU virt has
// no i8042, so the compliant proof there is explicit no-device absence.

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

static const char *driver = "i8042-kbd";
static const char *dev = "i8042";

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

static void driver_path(char *buf, size_t len, const char *leaf) {
    snprintf(buf, len, "/sys/bus/platform/drivers/%s/%s", driver, leaf);
}

static int lstat_path(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

static int driver_link_present(void) {
    char path[128];
    driver_path(path, sizeof path, dev);
    return lstat_path(path);
}

static int starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int count_i8042_devices(int *seen_exact) {
    DIR *d = opendir("/sys/bus/platform/devices");
    if (!d) {
        emitf("b590_ps2_singleton_device: FAIL opendir errno=%d\n", errno);
        return -1;
    }
    int count = 0;
    *seen_exact = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (!starts_with(de->d_name, "i8042")) continue;
        count++;
        if (strcmp(de->d_name, "i8042") == 0) {
            *seen_exact = 1;
        } else {
            emitf("b590_ps2_singleton_device: FAIL unexpected=%s\n", de->d_name);
        }
    }
    closedir(d);
    return count;
}

static int prove_i8042_singleton_x86(void) {
    int seen_exact = 0;
    int count = count_i8042_devices(&seen_exact);
    if (count != 1 || !seen_exact) {
        emitf("b590_ps2_singleton_device: FAIL count=%d i8042=%d\n",
              count, seen_exact);
        return 1;
    }
    if (!lstat_path("/sys/bus/platform/drivers/i8042-kbd")) {
        emitf("b590_ps2_singleton_driver: FAIL missing i8042-kbd\n");
        return 1;
    }
    emitf("b590_ps2_singleton_device: PASS device=i8042 count=%d\n", count);
    emitf("b590_ps2_singleton_driver: PASS driver=i8042-kbd\n");
    return 0;
}

static int writable_attr(const char *leaf, const char *tag) {
    char path[128];
    driver_path(path, sizeof path, leaf);
    if (access(path, W_OK) == 0) return 0;
    emitf("%s: FAIL path=%s errno=%d\n", tag, path, errno);
    return 1;
}

static int write_attr(const char *leaf, const char *tag, int quiet) {
    char path[128];
    driver_path(path, sizeof path, leaf);
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
    if (!quiet) emitf("%s: PASS\n", tag);
    return 0;
}

static int duplicate_bind_rejects(void) {
    char path[128];
    driver_path(path, sizeof path, "bind");
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        emitf("b586_duplicate_bind_open: FAIL errno=%d\n", errno);
        return 1;
    }
    ssize_t n = write(fd, dev, strlen(dev));
    int saved = errno;
    close(fd);
    if (n >= 0 || saved != EBUSY) {
        emitf("b586_duplicate_bind_ebusy: FAIL n=%ld errno=%d\n", (long)n, saved);
        return 1;
    }
    emitf("b586_duplicate_bind_ebusy: PASS errno=%d\n", saved);
    return 0;
}

static int wait_link(int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (driver_link_present() == want) return 0;
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

static int prove_bound_links(int loop) {
    char driver_dev[128];
    driver_path(driver_dev, sizeof driver_dev, dev);
    if (!lstat_path(driver_dev)) {
        emitf("b586_driver_link_present: FAIL loop=%d\n", loop);
        return 1;
    }
    if (readlink_has(driver_dev, "/devices/platform/i8042", "b586_driver_link_target")) return 1;
    if (readlink_has("/sys/devices/platform/i8042/driver",
                     "/bus/platform/drivers/i8042-kbd", "b586_device_driver_link")) return 1;
    return 0;
}

static int prove_unbound_links(int loop) {
    char driver_dev[128];
    driver_path(driver_dev, sizeof driver_dev, dev);
    if (lstat_path(driver_dev)) {
        emitf("b586_driver_link_absent: FAIL loop=%d\n", loop);
        return 1;
    }
    if (lstat_path("/sys/devices/platform/i8042/driver")) {
        emitf("b586_device_driver_absent: FAIL loop=%d\n", loop);
        return 1;
    }
    if (!lstat_path("/sys/devices/platform/i8042")) {
        emitf("b586_platform_device_persistent: FAIL loop=%d\n", loop);
        return 1;
    }
    return 0;
}

#if defined(__aarch64__)
static int prove_no_i8042_on_arm(void) {
    int seen_exact = 0;
    int count = count_i8042_devices(&seen_exact);
    if (count != 0 || seen_exact) {
        emitf("b590_ps2_arm_no_singleton: FAIL count=%d i8042=%d\n",
              count, seen_exact);
        return 1;
    }
    if (lstat_path("/sys/devices/platform/i8042")) {
        emitf("b586_arm_no_i8042_device: FAIL device exists\n");
        return 1;
    }
    if (lstat_path("/sys/bus/platform/drivers/i8042-kbd")) {
        emitf("b586_arm_no_i8042_driver: FAIL driver exists\n");
        return 1;
    }
    emitf("b586_arm_no_i8042_device: PASS\n");
    emitf("b586_arm_no_i8042_driver: PASS\n");
    emitf("b590_ps2_arm_no_singleton: PASS count=%d\n", count);
    emitf("driver_path_smoke: PASS - ps2-rebind\n");
    return 0;
}
#endif

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mount_api_fs();
    emitf("ps2_rebind_probe: START\n");

#if defined(__aarch64__)
    return prove_no_i8042_on_arm();
#else
    if (!lstat_path("/sys/devices/platform/i8042")) {
        emitf("b586_i8042_device_present: FAIL missing platform device\n");
        return 1;
    }
    if (prove_i8042_singleton_x86()) return 1;
    if (writable_attr("bind", "b586_bind_attr") ||
        writable_attr("unbind", "b586_unbind_attr") ||
        prove_bound_links(0) ||
        duplicate_bind_rejects()) return 1;

    for (int loop = 1; loop <= LOOPS; loop++) {
        emitf("b586_ps2_rebind_loop: START loop=%d driver=%s dev=%s\n", loop, driver, dev);
        if (write_attr("unbind", "b586_unbind_write", 0)) return 1;
        if (wait_link(0) || prove_unbound_links(loop)) {
            emitf("b586_ps2_unbind: FAIL loop=%d\n", loop);
            return 1;
        }
        emitf("b586_driver_link_absent: PASS loop=%d driver=%s\n", loop, driver);
        emitf("b586_device_driver_absent: PASS loop=%d driver=%s\n", loop, driver);
        emitf("b586_platform_device_persistent: PASS loop=%d\n", loop);
        if (write_attr("bind", "b586_bind_write", 0)) return 1;
        if (wait_link(1)) {
            emitf("b586_driver_link_restored: FAIL loop=%d\n", loop);
            return 1;
        }
        if (prove_bound_links(loop)) return 1;
        emitf("b586_ps2_rebind_loop: PASS loop=%d driver=%s dev=%s\n", loop, driver, dev);
    }
    emitf("driver_path_smoke: PASS - ps2-rebind\n");
    return 0;
#endif
}
