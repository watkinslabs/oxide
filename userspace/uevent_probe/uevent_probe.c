// /bin/uevent_probe — NETLINK_KOBJECT_UEVENT broadcast (K5). udev /
// systemd-udevd bind this netlink protocol to receive device add/remove
// uevents. Binds the socket, triggers a uevent by writing "change" to
// /sys/class/net/eth0/uevent (the udevadm-trigger path), and verifies the
// broadcast message arrives carrying ACTION=change.

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>

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

int main(void) {
    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    if (s < 0) { printf("uevent_probe: FAIL socket errno=%d\n", errno); return 1; }

    struct sockaddr_nl_ sa;
    memset(&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = 1;                 // subscribe to the uevent broadcast group
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("uevent_probe: FAIL bind errno=%d\n", errno); return 1;
    }

    // Trigger a uevent the udev way: write an action to the sysfs node.
    int uf = open("/sys/class/net/eth0/uevent", O_WRONLY);
    if (uf < 0) { printf("uevent_probe: FAIL open uevent errno=%d\n", errno); return 1; }
    if (write(uf, "change\n", 7) < 0) { printf("uevent_probe: FAIL write uevent errno=%d\n", errno); return 1; }
    close(uf);

    // Receive the broadcast (NUL-separated env blob).
    char buf[512];
    int n = recv(s, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { printf("uevent_probe: FAIL recv n=%d errno=%d\n", n, errno); return 1; }

    int ok = 0;
    for (int i = 0; i + 13 <= n; i++)
        if (memcmp(buf + i, "ACTION=change", 13) == 0) { ok = 1; break; }
    if (!ok) { printf("uevent_probe: FAIL no ACTION=change in %d bytes\n", n); return 1; }

    printf("uevent_probe: PASS netlink KOBJECT_UEVENT broadcast\n");
    return 0;
}
