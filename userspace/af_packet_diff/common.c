#include "probe.h"

void out(const char *area, const char *test, const char *fmt, ...) {
    va_list ap;
    printf("%s|%s|", area, test);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
}

const char *errno_name(int err) {
    switch (err) {
    case 0: return "OK";
    case EACCES: return "EACCES";
    case EAGAIN: return "EAGAIN";
    case EALREADY: return "EALREADY";
    case EBADF: return "EBADF";
    case EBUSY: return "EBUSY";
    case EEXIST: return "EEXIST";
    case EFAULT: return "EFAULT";
    case EINVAL: return "EINVAL";
    case ENODEV: return "ENODEV";
    case ENOENT: return "ENOENT";
    case ENOMEM: return "ENOMEM";
    case ENOPROTOOPT: return "ENOPROTOOPT";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case ENOSPC: return "ENOSPC";
    case ENOTCONN: return "ENOTCONN";
    case EPERM: return "EPERM";
    default: return "OTHER";
    }
}

void result(const char *area, const char *test, int rc, int err) {
    out(area, test, "rc=%d|errno=%s(%d)", rc, errno_name(err), err);
}

int packet_socket(int type, int protocol) {
    return socket(AF_PACKET, type | SOCK_NONBLOCK, htons((uint16_t)protocol));
}

int bind_packet(int fd, int ifindex, int protocol) {
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons((uint16_t)protocol);
    addr.sll_ifindex = ifindex;
    return bind(fd, (struct sockaddr *)&addr, sizeof(addr));
}

int send_frame(int ifindex, int protocol, unsigned int sequence) {
    unsigned char frame[64];
    struct sockaddr_ll addr;
    int fd = packet_socket(SOCK_RAW, protocol);
    if (fd < 0) return -1;
    memset(frame, 0, sizeof(frame));
    memset(frame, 0xff, ETH_ALEN);
    frame[12] = (unsigned char)(protocol >> 8);
    frame[13] = (unsigned char)protocol;
    memcpy(frame + 14, "AF_PACKET_DIFF", 14);
    memcpy(frame + 32, &sequence, sizeof(sequence));
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons((uint16_t)protocol);
    addr.sll_ifindex = ifindex;
    int rc = (int)sendto(fd, frame, sizeof(frame), 0,
                         (struct sockaddr *)&addr, sizeof(addr));
    int saved = errno;
    close(fd);
    errno = saved;
    return rc;
}

int send_udp_burst(unsigned int count) {
    struct sockaddr_in addr;
    unsigned char payload[512];
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    memset(payload, 0x5a, sizeof(payload));
    int sent = 0;
    for (unsigned int i = 0; i < count; i++) {
        memcpy(payload, &i, sizeof(i));
        if (sendto(fd, payload, sizeof(payload), 0,
                   (struct sockaddr *)&addr, sizeof(addr)) >= 0) sent++;
    }
    close(fd);
    return sent;
}

int poll_mask(int fd, short events, int timeout_ms) {
    struct pollfd pfd = {.fd = fd, .events = events};
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return rc;
    return pfd.revents;
}

int drain_packets(int fd) {
    unsigned char buf[4096];
    int count = 0;
    while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) >= 0) count++;
    return count;
}

void *fault_page(size_t *size) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return MAP_FAILED;
    *size = (size_t)page_size;
    return mmap(NULL, *size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}
