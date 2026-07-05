// /bin/uevent_probe — NETLINK_KOBJECT_UEVENT broadcast + bind/unbind proof.

#define _GNU_SOURCE
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>

#define UEVENT_GROUP 1
#define RECV_POLLS 200
#define RECV_SLEEP_US 10000
#define MAX_DEVS 8
#define MAX_NAME 64
#define MAX_PATH 160
#define UEVENT_BUF 2048
#define ACTION_CHANGE "ACTION=change"
#define SUBSYSTEM_NET "SUBSYSTEM=net"
#define SUBSYSTEM_VIRTIO "SUBSYSTEM=virtio"
#define DRIVER_VIRTIO_SND "DRIVER=virtio-snd"

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif
#ifndef NETLINK_KOBJECT_UEVENT
#define NETLINK_KOBJECT_UEVENT 15
#endif

struct sockaddr_nl_ {
    unsigned short nl_family;
    unsigned short nl_pad;
    unsigned int   nl_pid;
    unsigned int   nl_groups;
};

static const char *snd_driver = "/sys/bus/virtio/drivers/virtio-snd";

static int has_entry(const char *buf, int n, const char *want) {
    int wl = strlen(want);
    for (int i = 0; i + wl <= n; i++) {
        if ((i == 0 || buf[i - 1] == '\0') &&
            memcmp(buf + i, want, wl) == 0 &&
            (i + wl == n || buf[i + wl] == '\0')) return 1;
    }
    return 0;
}

static int recv_match(int s, const char *tag, const char *a, const char *b,
                      const char *c, const char *d, const char *reject) {
    char buf[UEVENT_BUF];
    for (int poll = 0; poll < RECV_POLLS; poll++) {
        int n = recv(s, buf, sizeof buf, 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(RECV_SLEEP_US);
            continue;
        }
        if (n <= 0) {
            printf("%s: FAIL recv n=%d errno=%d\n", tag, n, errno);
            return 1;
        }
        if (has_entry(buf, n, a) &&
            (!b || has_entry(buf, n, b)) &&
            (!c || has_entry(buf, n, c)) &&
            (!d || has_entry(buf, n, d)) &&
            (!reject || !has_entry(buf, n, reject))) {
            printf("%s: PASS\n", tag);
            return 0;
        }
    }
    printf("%s: FAIL matching uevent not received\n", tag);
    return 1;
}

static int write_token(const char *path, const char *token, const char *tag) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) { printf("%s: FAIL open errno=%d\n", tag, errno); return 1; }
    ssize_t n = write(fd, token, strlen(token));
    int saved = errno;
    close(fd);
    if (n != (ssize_t)strlen(token)) {
        printf("%s: FAIL write n=%ld errno=%d\n", tag, (long)n, saved);
        return 1;
    }
    return 0;
}

static int list_bound(char names[MAX_DEVS][MAX_NAME]) {
    DIR *d = opendir(snd_driver);
    if (!d) { printf("uevent_probe: FAIL opendir virtio-snd errno=%d\n", errno); return -1; }
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

static int wait_bound(const char *name, int want) {
    for (int i = 0; i < RECV_POLLS; i++) {
        if (device_bound(name) == want) return 0;
        usleep(RECV_SLEEP_US);
    }
    return 1;
}

static int open_uevent_socket(void) {
    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    if (s < 0) { printf("uevent_probe: FAIL socket errno=%d\n", errno); return -1; }

    struct sockaddr_nl_ sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = UEVENT_GROUP;
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("uevent_probe: FAIL bind errno=%d\n", errno);
        close(s);
        return -1;
    }
    int fl = fcntl(s, F_GETFL, 0);
    if (fl >= 0) fcntl(s, F_SETFL, fl | O_NONBLOCK);
    return s;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int s = open_uevent_socket();
    if (s < 0) return 1;

    if (write_token("/sys/class/net/eth0/uevent", "change\n",
                    "uevent_probe_net_trigger")) return 1;
    if (recv_match(s, "uevent_probe_net_change", ACTION_CHANGE,
                   SUBSYSTEM_NET, NULL, NULL, NULL)) return 1;

    char names[MAX_DEVS][MAX_NAME];
    int count = list_bound(names);
    if (count <= 0) { printf("uevent_probe: FAIL no bound virtio-snd device count=%d\n", count); return 1; }
    const char *dev = names[0];
    char unbind_path[MAX_PATH], bind_path[MAX_PATH], devpath[MAX_PATH];
    snprintf(unbind_path, sizeof unbind_path, "%s/unbind", snd_driver);
    snprintf(bind_path, sizeof bind_path, "%s/bind", snd_driver);
    snprintf(devpath, sizeof devpath, "DEVPATH=/devices/virtio/%s", dev);

    if (write_token(unbind_path, dev, "uevent_probe_unbind_write")) return 1;
    if (wait_bound(dev, 0)) { printf("uevent_probe_unbind_state: FAIL\n"); return 1; }
    printf("uevent_probe_unbind_state: PASS\n");
    if (recv_match(s, "uevent_probe_unbind_change", ACTION_CHANGE,
                   SUBSYSTEM_VIRTIO, devpath, NULL, DRIVER_VIRTIO_SND)) return 1;

    if (write_token(bind_path, dev, "uevent_probe_bind_write")) return 1;
    if (wait_bound(dev, 1)) { printf("uevent_probe_bind_state: FAIL\n"); return 1; }
    printf("uevent_probe_bind_state: PASS\n");
    if (recv_match(s, "uevent_probe_bind_change", ACTION_CHANGE,
                   SUBSYSTEM_VIRTIO, devpath, DRIVER_VIRTIO_SND, NULL)) return 1;

    printf("uevent_probe: PASS netlink KOBJECT_UEVENT bind/unbind\n");
    return 0;
}
