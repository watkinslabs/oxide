// /bin/virtio_input_rebind_probe - virtio-input live sysfs rebind proof.
// Resolves /dev/input/event1's virtio parent, unbinds/rebinds that child, then
// runs mouseprobe so QMP-injected pointer events prove the restored evdev path.

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

static const char *driver = "/sys/bus/virtio/drivers/virtio-input";

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

static int event1_dev_present(void) {
    return access("/dev/input/event1", R_OK) == 0;
}

static int event1_sys_present(void) {
    return access("/sys/class/input/event1/dev", R_OK) == 0;
}

static int event1_present(void) {
    return event1_dev_present() && event1_sys_present();
}

static int pointer_parent(char out[MAX_NAME]) {
    char link[160];
    ssize_t n = readlink("/sys/class/input/event1/device", link, sizeof link - 1);
    if (n <= 0) {
        printf("b576_event1_parent: FAIL readlink n=%ld errno=%d\n", (long)n, errno);
        return 1;
    }
    link[n] = '\0';
    const char *base = strrchr(link, '/');
    base = base ? base + 1 : link;
    if (strncmp(base, "virtio", 6) != 0) {
        printf("b576_event1_parent: FAIL target=%s\n", link);
        return 1;
    }
    strncpy(out, base, MAX_NAME - 1);
    out[MAX_NAME - 1] = '\0';
    printf("b576_event1_parent: PASS %s\n", out);
    emit_line("b576_event1_parent: PASS\n");
    return 0;
}

static int list_bound(char names[MAX_DEVS][MAX_NAME]) {
    DIR *d = opendir(driver);
    if (!d) {
        printf("b576_bound_devices: FAIL opendir errno=%d\n", errno);
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

static int wait_event1(int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (event1_present() == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int wait_event1_path(int want, int (*present)(void)) {
    for (int i = 0; i < RETRIES; i++) {
        if (present() == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int run_mouseprobe(void) {
    pid_t pid = fork();
    if (pid < 0) {
        printf("b576_mouseprobe: FAIL fork errno=%d\n", errno);
        return 1;
    }
    if (pid == 0) {
        execl("/bin/mouseprobe", "/bin/mouseprobe", (char *)0);
        _exit(127);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) {
        printf("b576_mouseprobe: FAIL wait errno=%d\n", errno);
        return 1;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("b576_mouseprobe: FAIL status=%d\n", st);
        return 1;
    }
    printf("b576_mouseprobe: PASS\n");
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    emit_line("virtio_input_rebind_probe: START\n");
    mount_api_fs();

    if (!event1_present()) {
        printf("b576_event1_initial: FAIL\n");
        return 1;
    }
    emit_line("b576_event1_initial: PASS\n");
    char dev[MAX_NAME];
    if (pointer_parent(dev)) return 1;
    if (!device_bound(dev)) {
        printf("b576_pointer_bound: FAIL %s\n", dev);
        return 1;
    }

    if (write_token("unbind", dev, "b576_unbind_write")) return 1;
    emit_line("b576_unbind_write: PASS\n");
    if (wait_bound(dev, 0)) {
        emit_line("b576_virtio_input_unbind: FAIL bound\n");
        return 1;
    }
    if (wait_event1_path(0, event1_dev_present)) {
        emit_line("b576_virtio_input_unbind: FAIL dev\n");
        return 1;
    }
    if (wait_event1_path(0, event1_sys_present)) {
        emit_line("b576_virtio_input_unbind: FAIL sys\n");
        return 1;
    }
    emit_line("b576_virtio_input_unbind: PASS\n");

    if (write_token("bind", dev, "b576_bind_write")) return 1;
    emit_line("b576_bind_write: PASS\n");
    if (wait_bound(dev, 1)) {
        emit_line("b576_virtio_input_rebind: FAIL bound\n");
        return 1;
    }
    if (wait_event1(1)) {
        emit_line("b576_virtio_input_rebind: FAIL event1\n");
        return 1;
    }
    emit_line("b576_virtio_input_rebind: PASS\n");
    emit_line("driver_path_smoke: run mouseprobe\n");
    if (run_mouseprobe()) return 1;
    emit_line("driver_path_smoke: PASS - virtio-input-rebind\n");
    return 0;
}
