// /bin/virtio_gpu_multidev_probe — virtio-gpu multi-card sysfs rebind proof.
// Proves two DRM card nodes exist, virtio-gpu bind/unbind are writable, and
// unbinding/rebinding one virtio child removes then restores its sysfs card.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_DEVS 8
#define MAX_NAME 64
#define MAX_PATH 128
#define MAX_CARDS 8
#define RETRIES 50
#define SLEEP_US 100000
#define REBIND_LOOPS 3

#define DRM_IOCTL_MODE_GETRESOURCES  _IOWR(0x64, 0xa0, struct drm_mode_card_res)

struct drm_mode_card_res {
    uint64_t fb_id_ptr;
    uint64_t crtc_id_ptr;
    uint64_t connector_id_ptr;
    uint64_t encoder_id_ptr;
    uint32_t count_fbs;
    uint32_t count_crtcs;
    uint32_t count_connectors;
    uint32_t count_encoders;
    uint32_t min_width, max_width;
    uint32_t min_height, max_height;
};

static const char *driver = "/sys/bus/virtio/drivers/virtio-gpu";

static void emit_line(const char *msg) {
    write(1, msg, strlen(msg));
    int fd = open("/dev/kmsg", O_WRONLY);
    if (fd >= 0) {
        write(fd, msg, strlen(msg));
        close(fd);
    }
}

static int emitf(const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return n;
    size_t len = (size_t)n;
    if (len >= sizeof buf) len = sizeof buf - 1;
    write(1, buf, len);
    int fd = open("/dev/kmsg", O_WRONLY);
    if (fd >= 0) {
        write(fd, buf, len);
        close(fd);
    }
    return n;
}

#define printf(...) emitf(__VA_ARGS__)

static void mount_api_fs(void) {
    mount("proc", "/proc", "proc", 0, "");
    mount("sysfs", "/sys", "sysfs", 0, "");
    mount("tmpfs", "/tmp", "tmpfs", 0, "");
    mount("devpts", "/dev/pts", "devpts", 0, "");
}

static int run_probe(const char *path) {
    pid_t pid = fork();
    if (pid < 0) {
        printf("virtio_gpu_multidev_probe: FAIL fork %s errno=%d\n", path, errno);
        return 1;
    }
    if (pid == 0) { execl(path, path, (char *)0); _exit(127); }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) {
        printf("virtio_gpu_multidev_probe: FAIL wait %s errno=%d\n", path, errno);
        return 1;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("virtio_gpu_multidev_probe: FAIL child %s status=%d\n", path, st);
        return 1;
    }
    return 0;
}

static int list_bound(char names[MAX_DEVS][MAX_NAME]) {
    DIR *d = opendir(driver);
    if (!d) { printf("b418_bound_devices: FAIL opendir errno=%d\n", errno); return -1; }
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

static int write_token(const char *leaf, const char *token, const char *tag) {
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s/%s", driver, leaf);
    int fd = open(path, O_WRONLY);
    if (fd < 0) { printf("%s: FAIL open errno=%d\n", tag, errno); return 1; }
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

static void emit_status(const char *tag, const char *status) {
    char line[96];
    int n = snprintf(line, sizeof line, "%s: %s\n", tag, status);
    if (n > 0) emit_line(line);
}

static int missing(const char *path, const char *tag) {
    errno = 0;
    if (access(path, F_OK) < 0 && errno == ENOENT) return 0;
    printf("%s: FAIL path=%s errno=%d\n", tag, path, errno);
    emit_status(tag, "FAIL");
    return 1;
}

static int open_missing(const char *path, const char *tag) {
    errno = 0;
    int fd = open(path, O_RDWR);
    int saved = errno;
    if (fd >= 0) {
        close(fd);
        printf("%s: FAIL path=%s still-openable\n", tag, path);
        return 1;
    }
    if (saved != ENOENT) {
        printf("%s: FAIL path=%s errno=%d\n", tag, path, saved);
        return 1;
    }
    printf("%s: PASS errno=%d\n", tag, saved);
    return 0;
}

static int count_cards(void) {
    int n = 0;
    char path[MAX_PATH];
    for (int i = 0; i < MAX_CARDS; i++) {
        snprintf(path, sizeof path, "/dev/dri/card%d", i);
        int fd = open(path, O_RDWR);
        if (fd >= 0) {
            close(fd);
            n++;
        }
    }
    return n;
}

static int count_sysfs_cards(void) {
    int n = 0;
    char path[MAX_PATH];
    for (int i = 0; i < MAX_CARDS; i++) {
        snprintf(path, sizeof path, "/sys/class/drm/card%d", i);
        if (access(path, F_OK) == 0) n++;
    }
    return n;
}

static int wait_card_count(int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (count_cards() == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int wait_sysfs_card_count(int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (count_sysfs_cards() == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int prove_card(const char *path, const char *tag) {
    int fd = open(path, O_RDWR);
    if (fd < 0) { printf("%s: FAIL open errno=%d\n", tag, errno); return 1; }
    struct drm_mode_card_res res;
    memset(&res, 0, sizeof res);
    if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) {
        printf("%s: FAIL GETRESOURCES errno=%d\n", tag, errno);
        close(fd);
        return 1;
    }
    close(fd);
    if (res.count_crtcs < 1 || res.count_connectors < 1 || res.count_encoders < 1) {
        printf("%s: FAIL resources crtcs=%u conns=%u encs=%u\n",
               tag, res.count_crtcs, res.count_connectors, res.count_encoders);
        return 1;
    }
    printf("%s: PASS crtcs=%u conns=%u encs=%u\n",
           tag, res.count_crtcs, res.count_connectors, res.count_encoders);
    return 0;
}

static int prove_removed_second_card(int iter) {
    if (wait_sysfs_card_count(1) || wait_card_count(1)) {
        printf("b579_cards_after_unbind_%d: FAIL sysfs=%d devfs=%d\n",
               iter, count_sysfs_cards(), count_cards());
        return 1;
    }
    char tag[64];
    snprintf(tag, sizeof tag, "b579_removed_dev_card1_%d", iter);
    if (missing("/dev/dri/card1", tag)) return 1;
    snprintf(tag, sizeof tag, "b587_removed_dev_card1_open_%d", iter);
    if (open_missing("/dev/dri/card1", tag)) return 1;
    snprintf(tag, sizeof tag, "b579_removed_sys_card1_%d", iter);
    if (missing("/sys/class/drm/card1", tag)) return 1;
    emit_status("b579_cards_after_unbind", "PASS");
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    emit_line("virtio_gpu_multidev_probe: START\n");
    mount_api_fs();
    if (run_probe("/bin/fbdev_probe") || run_probe("/bin/sysblock_probe") ||
        run_probe("/bin/snd_probe") || run_probe("/bin/rtlink_probe")) return 1;

    if (wait_card_count(2)) {
        printf("b418_drm_cards_initial: FAIL count=%d\n", count_cards());
        return 1;
    }
    if (prove_card("/dev/dri/card0", "b418_card0_initial") ||
        prove_card("/dev/dri/card1", "b418_card1_initial")) return 1;

    char names[MAX_DEVS][MAX_NAME];
    int n = list_bound(names);
    printf("b418_bound_devices:");
    for (int i = 0; i < n && i < MAX_DEVS; i++) printf(" %s", names[i]);
    printf("\n");
    if (n < 2) { printf("b418_bound_devices: FAIL count=%d\n", n); return 1; }

    const char *dev = names[1];
    for (int iter = 0; iter < REBIND_LOOPS; iter++) {
        char tag[64];
        snprintf(tag, sizeof tag, "b579_loop_%d", iter);
        emit_status(tag, "START");
        printf("b579_unbind_dev_%d: %s\n", iter, dev);
        if (write_token("unbind", dev, "b579_unbind_write")) return 1;
        if (device_bound(dev)) { printf("b579_virtio_gpu_unbind_%d: FAIL still-bound\n", iter); return 1; }
        if (prove_removed_second_card(iter)) return 1;
        emit_status("b579_virtio_gpu_unbind", "PASS");

        if (write_token("bind", dev, "b579_bind_write")) return 1;
        if (!device_bound(dev)) { printf("b579_virtio_gpu_rebind_%d: FAIL not-bound\n", iter); return 1; }
        if (wait_sysfs_card_count(2) || wait_card_count(2)) {
            printf("b579_cards_after_rebind_%d: FAIL sysfs=%d devfs=%d\n",
                   iter, count_sysfs_cards(), count_cards());
            return 1;
        }
        snprintf(tag, sizeof tag, "b579_card0_loop%d", iter);
        if (prove_card("/dev/dri/card0", tag)) return 1;
        snprintf(tag, sizeof tag, "b579_card1_loop%d", iter);
        if (prove_card("/dev/dri/card1", tag)) return 1;
        emit_status("b579_virtio_gpu_rebind", "PASS");
    }
    emit_line("driver_path_smoke: run mouseprobe\n");
    sleep(1);
    if (run_probe("/bin/mouseprobe")) return 1;
    emit_line("driver_path_smoke: PASS - GPU input sound block net virtio-gpu-multidev-rebind\n");
    return 0;
}
