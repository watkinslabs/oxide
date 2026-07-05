// /bin/virtio_net_multidev_probe — virtio-net multi-device sysfs rebind proof.
// Proves two eth interfaces exist, virtio-net driver bind/unbind are writable,
// and a selected bound virtio child disappears/reappears from driver readdir.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_DEVS 8
#define MAX_NAME 64
#define RETRIES 50
#define SLEEP_US 100000

static const char *driver = "/sys/bus/virtio/drivers/virtio-net";

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

static int run_probe(const char *path) {
    pid_t pid = fork();
    if (pid < 0) {
        printf("virtio_net_multidev_probe: FAIL fork %s errno=%d\n", path, errno);
        emit_line("virtio_net_multidev_probe: FAIL fork\n");
        return 1;
    }
    if (pid == 0) { execl(path, path, (char *)0); _exit(127); }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) {
        printf("virtio_net_multidev_probe: FAIL wait %s errno=%d\n", path, errno);
        emit_line("virtio_net_multidev_probe: FAIL wait\n");
        return 1;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("virtio_net_multidev_probe: FAIL child %s status=%d\n", path, st);
        emit_line("virtio_net_multidev_probe: FAIL child\n");
        return 1;
    }
    return 0;
}

static int readable(const char *path, const char *tag) {
    if (access(path, R_OK) == 0) return 0;
    printf("%s: FAIL path=%s errno=%d\n", tag, path, errno);
    return 1;
}

static int writable(const char *path, const char *tag) {
    if (access(path, W_OK) == 0) return 0;
    printf("%s: FAIL path=%s errno=%d\n", tag, path, errno);
    return 1;
}

static int list_bound(char names[MAX_DEVS][MAX_NAME]) {
    DIR *d = opendir(driver);
    if (!d) { printf("b382_bound_devices: FAIL opendir errno=%d\n", errno); return -1; }
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
    char path[128];
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

static int wait_bound(const char *name, int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (device_bound(name) == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int count_eth(void) {
    DIR *d = opendir("/sys/class/net");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strncmp(e->d_name, "eth", 3)) n++;
    }
    closedir(d);
    return n;
}

static int wait_eth_count(int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (count_eth() >= want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    emit_line("virtio_net_multidev_probe: START\n");
    mount_api_fs();
    if (run_probe("/bin/fbdev_probe") || run_probe("/bin/drm_probe") ||
        run_probe("/bin/sysblock_probe") || run_probe("/bin/snd_probe") ||
        run_probe("/bin/rtlink_probe")) return 1;

    if (readable("/sys/class/net/eth0/address", "b382_eth0_address") ||
        readable("/sys/class/net/eth1/address", "b382_eth1_address") ||
        readable("/sys/class/net/eth0/statistics/rx_packets", "b382_eth0_rx_packets") ||
        readable("/sys/class/net/eth1/statistics/rx_packets", "b382_eth1_rx_packets") ||
        writable("/sys/bus/virtio/drivers/virtio-net/bind", "b382_bind_attr") ||
        writable("/sys/bus/virtio/drivers/virtio-net/unbind", "b382_unbind_attr")) return 1;
    emit_line("b382_net_eth0_eth1: PASS\n");

    char names[MAX_DEVS][MAX_NAME];
    int n = list_bound(names);
    printf("b382_bound_devices:");
    for (int i = 0; i < n && i < MAX_DEVS; i++) printf(" %s", names[i]);
    printf("\n");
    if (n < 2) { printf("b382_bound_devices: FAIL count=%d\n", n); return 1; }

    const char *dev = names[1];
    printf("b382_unbind_dev: %s\n", dev);
    if (write_token("unbind", dev, "b382_unbind_write")) return 1;
    if (wait_bound(dev, 0)) { printf("b382_virtio_net_unbind: FAIL\n"); return 1; }
    emit_line("b382_virtio_net_unbind: PASS\n");

    if (write_token("bind", dev, "b382_bind_write")) return 1;
    if (wait_bound(dev, 1)) { printf("b382_virtio_net_rebind: FAIL\n"); return 1; }
    if (wait_eth_count(2) ||
        readable("/sys/class/net/eth0/address", "b382_re_eth0_address") ||
        readable("/sys/class/net/eth1/address", "b382_re_eth1_address")) return 1;
    emit_line("b382_virtio_net_rebind: PASS\n");
    emit_line("driver_path_smoke: run mouseprobe\n");
    sleep(1);
    if (run_probe("/bin/mouseprobe")) return 1;
    emit_line("driver_path_smoke: PASS - GPU input sound block net multidev-rebind\n");
    return 0;
}
