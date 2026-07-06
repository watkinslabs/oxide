// /bin/virtio_rng_rebind_probe - virtio-rng live sysfs rebind proof.
// Boots with two virtio-rng devices, unbinds one child, proves /dev/hwrng
// remains backed by the promoted provider, then rebinds the child.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#define MAX_DEVS 8
#define MAX_NAME 64
#define RETRIES 50
#define SLEEP_US 100000

static const char *driver = "/sys/bus/virtio/drivers/virtio-rng";

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

static int read_hwrng(const char *tag) {
    int fd = open("/dev/hwrng", O_RDONLY);
    if (fd < 0) {
        printf("%s: FAIL open errno=%d\n", tag, errno);
        return 1;
    }
    unsigned char buf[32];
    memset(buf, 0, sizeof buf);
    ssize_t n = read(fd, buf, sizeof buf);
    int saved = errno;
    close(fd);
    if (n <= 0) {
        printf("%s: FAIL read n=%ld errno=%d\n", tag, (long)n, saved);
        return 1;
    }
    int all_equal = 1;
    for (ssize_t i = 1; i < n; i++) {
        if (buf[i] != buf[0]) {
            all_equal = 0;
            break;
        }
    }
    if (all_equal) {
        printf("%s: FAIL all bytes equal\n", tag);
        return 1;
    }
    printf("%s: PASS n=%ld\n", tag, (long)n);
    return 0;
}

static int list_bound(char names[MAX_DEVS][MAX_NAME]) {
    DIR *d = opendir(driver);
    if (!d) {
        printf("b574_bound_devices: FAIL opendir errno=%d\n", errno);
        return -1;
    }
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

static int device_bound(const char *name) {
    char names[MAX_DEVS][MAX_NAME];
    int n = list_bound(names);
    if (n < 0) return 0;
    for (int i = 0; i < n && i < MAX_DEVS; i++) {
        if (!strcmp(names[i], name)) return 1;
    }
    return 0;
}

static int writable(const char *leaf, const char *tag) {
    char path[128];
    snprintf(path, sizeof path, "%s/%s", driver, leaf);
    if (access(path, W_OK) == 0) return 0;
    printf("%s: FAIL path=%s errno=%d\n", tag, path, errno);
    return 1;
}

static int write_token(const char *leaf, const char *token, const char *tag) {
    char path[128];
    snprintf(path, sizeof path, "%s/%s", driver, leaf);
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        printf("%s: FAIL open errno=%d\n", tag, errno);
        return 1;
    }
    ssize_t n = write(fd, token, strlen(token));
    int saved = errno;
    close(fd);
    if (n != (ssize_t)strlen(token)) {
        printf("%s: FAIL write n=%ld errno=%d\n", tag, (long)n, saved);
        return 1;
    }
    printf("%s: PASS\n", tag);
    return 0;
}

static int wait_bound(const char *name, int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (device_bound(name) == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    emit_line("virtio_rng_rebind_probe: START\n");
    mount_api_fs();

    if (writable("bind", "b574_bind_attr") ||
        writable("unbind", "b574_unbind_attr") ||
        read_hwrng("b574_hwrng_initial")) return 1;

    char names[MAX_DEVS][MAX_NAME];
    int n = list_bound(names);
    printf("b574_bound_devices:");
    for (int i = 0; i < n && i < MAX_DEVS; i++) printf(" %s", names[i]);
    printf("\n");
    if (n < 2) {
        printf("b574_bound_devices: FAIL count=%d\n", n);
        return 1;
    }

    const char *dev = names[0];
    printf("b574_unbind_dev: %s\n", dev);
    if (write_token("unbind", dev, "b574_unbind_write")) return 1;
    if (wait_bound(dev, 0)) {
        printf("b574_virtio_rng_unbind: FAIL\n");
        return 1;
    }
    emit_line("b574_virtio_rng_unbind: PASS\n");
    if (read_hwrng("b574_hwrng_after_unbind")) return 1;

    if (write_token("bind", dev, "b574_bind_write")) return 1;
    if (wait_bound(dev, 1)) {
        printf("b574_virtio_rng_rebind: FAIL\n");
        return 1;
    }
    if (read_hwrng("b574_hwrng_after_rebind")) return 1;
    emit_line("b574_virtio_rng_rebind: PASS\n");
    emit_line("driver_path_smoke: PASS - virtio-rng-rebind\n");
    return 0;
}
