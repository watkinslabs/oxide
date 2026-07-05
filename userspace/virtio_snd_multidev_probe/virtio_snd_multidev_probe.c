// /bin/virtio_snd_multidev_probe — virtio-snd multi-card sysfs rebind proof.
// Proves two ALSA cards exist, virtio-snd driver bind/unbind are writable,
// and unbinding one virtio child removes one card while another remains.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_DEVS 8
#define MAX_NAME 64
#define MAX_PATH 128
#define RETRIES 50
#define SLEEP_US 100000
#define STREAM_PLAYBACK 0
#define STREAM_CAPTURE 1
#define CTL_ELEM_IFACE_MIXER 2

struct snd_ctl_card_info {
    int card;
    int pad;
    unsigned char id[16], driver[16], name[32], longname[80],
                  reserved_[16], mixername[80], components[128];
};

struct snd_pcm_info {
    unsigned int device, subdevice, stream, card;
    unsigned char id[64], name[80], subname[32], pad[8];
    unsigned int subdevices_count, subdevices_avail;
    unsigned char reserved[80];
};

struct snd_ctl_elem_id {
    unsigned int numid, iface, device, subdevice;
    unsigned char name[44];
    unsigned int index;
};

struct snd_ctl_elem_list {
    unsigned int offset, space, used, count;
    struct snd_ctl_elem_id *pids;
    unsigned char reserved[56];
};

struct snd_ctl_elem_info {
    struct snd_ctl_elem_id id;
    unsigned int type, access, count, owner;
    unsigned char value[192];
};

#define CTL_CARD_INFO  _IOR('U', 0x01, struct snd_ctl_card_info)
#define CTL_ELEM_LIST  _IOWR('U', 0x10, struct snd_ctl_elem_list)
#define CTL_ELEM_INFO  _IOWR('U', 0x11, struct snd_ctl_elem_info)
#define CTL_SUBSCRIBE  _IOWR('U', 0x16, int)
#define CTL_PCM_NEXT   _IOWR('U', 0x30, int)
#define CTL_PCM_INFO   _IOWR('U', 0x31, struct snd_pcm_info)

static const char *driver = "/sys/bus/virtio/drivers/virtio-snd";

static void emit_line(const char *msg) {
    write(1, msg, strlen(msg));
    int fd = open("/dev/kmsg", O_WRONLY);
    if (fd >= 0) {
        write(fd, msg, strlen(msg));
        close(fd);
    }
}

static void emit_status(const char *tag, const char *status) {
    char line[96];
    int n = snprintf(line, sizeof line, "%s: %s\n", tag, status);
    if (n > 0) emit_line(line);
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
        printf("virtio_snd_multidev_probe: FAIL fork %s errno=%d\n", path, errno);
        emit_line("virtio_snd_multidev_probe: FAIL fork\n");
        return 1;
    }
    if (pid == 0) { execl(path, path, (char *)0); _exit(127); }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) {
        printf("virtio_snd_multidev_probe: FAIL wait %s errno=%d\n", path, errno);
        emit_line("virtio_snd_multidev_probe: FAIL wait\n");
        return 1;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("virtio_snd_multidev_probe: FAIL child %s status=%d\n", path, st);
        emit_line("virtio_snd_multidev_probe: FAIL child\n");
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
    if (!d) { printf("b399_bound_devices: FAIL opendir errno=%d\n", errno); return -1; }
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

static int wait_bound(const char *name, int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (device_bound(name) == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int count_controls(void) {
    DIR *d = opendir("/dev/snd");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strncmp(e->d_name, "controlC", 8)) n++;
    }
    closedir(d);
    return n;
}

static int wait_control_count(int want) {
    for (int i = 0; i < RETRIES; i++) {
        if (count_controls() == want) return 0;
        usleep(SLEEP_US);
    }
    return 1;
}

static int prove_two_cards(const char *tag) {
    if (wait_control_count(2)) {
        printf("%s: FAIL control_count=%d\n", tag, count_controls());
        return 1;
    }
    if (readable("/dev/snd/controlC0", "b399_controlC0") ||
        readable("/dev/snd/controlC1", "b399_controlC1") ||
        readable("/dev/snd/pcmC0D0p", "b399_pcmC0D0p") ||
        readable("/dev/snd/pcmC1D0p", "b399_pcmC1D0p") ||
        readable("/dev/snd/pcmC0D0c", "b399_pcmC0D0c") ||
        readable("/dev/snd/pcmC1D0c", "b399_pcmC1D0c")) return 1;
    printf("%s: PASS\n", tag);
    return 0;
}

static int expect_missing_elem(int fd, const char *tag) {
    struct snd_ctl_elem_info info;
    memset(&info, 0, sizeof info);
    info.id.numid = 1;
    info.id.iface = CTL_ELEM_IFACE_MIXER;
    errno = 0;
    if (ioctl(fd, CTL_ELEM_INFO, &info) == 0 || errno != ENOENT) {
        printf("%s: FAIL elem_info errno=%d\n", tag, errno);
        emit_status(tag, "FAIL");
        return 1;
    }
    return 0;
}

static int prove_control_card(const char *path, int want_card, const char *tag) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("%s: FAIL open errno=%d\n", tag, errno); emit_status(tag, "FAIL"); return 1; }
    struct snd_ctl_card_info ci;
    memset(&ci, 0, sizeof ci);
    if (ioctl(fd, CTL_CARD_INFO, &ci) < 0) {
        printf("%s: FAIL CARD_INFO errno=%d\n", tag, errno);
        emit_status(tag, "FAIL");
        close(fd);
        return 1;
    }
    if (ci.card != want_card || ci.name[0] == 0) {
        printf("%s: FAIL card=%d want=%d name0=%u\n", tag, ci.card, want_card, ci.name[0]);
        emit_status(tag, "FAIL");
        close(fd);
        return 1;
    }
    int dev = -1;
    if (ioctl(fd, CTL_PCM_NEXT, &dev) < 0 || dev != 0) {
        printf("%s: FAIL PCM_NEXT dev=%d errno=%d\n", tag, dev, errno);
        emit_status(tag, "FAIL");
        close(fd);
        return 1;
    }
    for (int stream = STREAM_PLAYBACK; stream <= STREAM_CAPTURE; stream++) {
        struct snd_pcm_info pi;
        memset(&pi, 0, sizeof pi);
        pi.device = 0;
        pi.stream = stream;
        if (ioctl(fd, CTL_PCM_INFO, &pi) < 0) {
            printf("%s: FAIL PCM_INFO stream=%d errno=%d\n", tag, stream, errno);
            emit_status(tag, "FAIL");
            close(fd);
            return 1;
        }
        if ((int)pi.card != want_card || pi.device != 0 || (int)pi.stream != stream) {
            printf("%s: FAIL PCM_INFO route card=%u dev=%u stream=%u\n",
                   tag, pi.card, pi.device, pi.stream);
            emit_status(tag, "FAIL");
            close(fd);
            return 1;
        }
    }
    struct snd_ctl_elem_id ids[2];
    struct snd_ctl_elem_list list;
    memset(ids, 0, sizeof ids);
    memset(&list, 0, sizeof list);
    list.space = 2;
    list.pids = ids;
    if (ioctl(fd, CTL_ELEM_LIST, &list) < 0) {
        printf("%s: FAIL ELEM_LIST errno=%d\n", tag, errno);
        emit_status(tag, "FAIL");
        close(fd);
        return 1;
    }
    if (list.used != 0 || list.count != 0 || ids[0].numid != 0 || ids[1].numid != 0) {
        printf("%s: FAIL fabricated controls used=%u count=%u id0=%u id1=%u\n",
               tag, list.used, list.count, ids[0].numid, ids[1].numid);
        emit_status(tag, "FAIL");
        close(fd);
        return 1;
    }
    if (expect_missing_elem(fd, tag)) {
        close(fd);
        return 1;
    }
    int sub = 1;
    if (ioctl(fd, CTL_SUBSCRIBE, &sub) < 0) {
        printf("%s: FAIL SUBSCRIBE errno=%d\n", tag, errno);
        emit_status(tag, "FAIL");
        close(fd);
        return 1;
    }
    close(fd);
    printf("%s: PASS\n", tag);
    emit_status(tag, "PASS");
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    emit_line("virtio_snd_multidev_probe: START\n");
    mount_api_fs();
    if (run_probe("/bin/fbdev_probe") || run_probe("/bin/drm_probe") ||
        run_probe("/bin/sysblock_probe") || run_probe("/bin/rtlink_probe")) return 1;

    if (writable("/sys/bus/virtio/drivers/virtio-snd/bind", "b399_bind_attr") ||
        writable("/sys/bus/virtio/drivers/virtio-snd/unbind", "b399_unbind_attr") ||
        prove_two_cards("b399_snd_cards_initial")) return 1;
    if (prove_control_card("/dev/snd/controlC0", 0, "b420_controlC0_initial") ||
        prove_control_card("/dev/snd/controlC1", 1, "b420_controlC1_initial")) return 1;

    char names[MAX_DEVS][MAX_NAME];
    int n = list_bound(names);
    printf("b399_bound_devices:");
    for (int i = 0; i < n && i < MAX_DEVS; i++) printf(" %s", names[i]);
    printf("\n");
    if (n < 2) { printf("b399_bound_devices: FAIL count=%d\n", n); return 1; }

    const char *dev = names[1];
    printf("b399_unbind_dev: %s\n", dev);
    if (write_token("unbind", dev, "b399_unbind_write")) return 1;
    if (wait_bound(dev, 0)) { printf("b399_virtio_snd_unbind: FAIL\n"); return 1; }
    if (wait_control_count(1)) {
        printf("b399_snd_cards_after_unbind: FAIL control_count=%d\n", count_controls());
        return 1;
    }
    emit_line("b399_virtio_snd_unbind: PASS\n");

    if (write_token("bind", dev, "b399_bind_write")) return 1;
    if (wait_bound(dev, 1)) { printf("b399_virtio_snd_rebind: FAIL\n"); return 1; }
    if (prove_two_cards("b399_snd_cards_after_rebind")) return 1;
    if (prove_control_card("/dev/snd/controlC0", 0, "b420_controlC0_after_rebind") ||
        prove_control_card("/dev/snd/controlC1", 1, "b420_controlC1_after_rebind")) return 1;
    if (run_probe("/bin/snd_probe")) return 1;

    emit_line("driver_path_smoke: PASS - GPU sound block net virtio-snd-multidev-rebind\n");
    return 0;
}
