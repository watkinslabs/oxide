#include "probe.h"

static void ordering_faults(void) {
    struct msghdr msg;
    struct iovec iov;
    size_t page_len;
    void *fault = fault_page(&page_len);
    int badfd;
    int badmsg;
    int badfd_errno;
    int badmsg_errno;

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    badfd = sendmsg(-1, &msg, 0);
    badfd_errno = errno;
    badmsg = sendmsg(-1, fault, 0);
    badmsg_errno = errno;
    out("sendmsg", "ordering_faults", "badfd=%d:%s(%d)|badfd_badmsg=%d:%s(%d)",
        badfd, errno_name(badfd_errno), badfd_errno,
        badmsg, errno_name(badmsg_errno), badmsg_errno);
    if (fault != MAP_FAILED) munmap(fault, page_len);
}

static void packet_destination(void) {
    int fd = packet_socket(SOCK_RAW, ETH_P_ALL);
    struct sockaddr_ll addr;
    struct iovec iov;
    struct msghdr msg;
    unsigned char frame[64];
    int rc;

    if (fd < 0) {
        out("sendmsg", "packet_destination", "socket=%d:%s(%d)", fd,
            errno_name(errno), errno);
        return;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = (int)if_nametoindex("lo");
    memset(frame, 0, sizeof(frame));
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = frame;
    iov.iov_len = sizeof(frame);
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    rc = (int)sendmsg(fd, &msg, MSG_DONTWAIT);
    out("sendmsg", "packet_destination", "rc=%d|errno=%s(%d)|ifindex=%d|len=%zu",
        rc, errno_name(rc < 0 ? errno : 0), rc < 0 ? errno : 0,
        addr.sll_ifindex, sizeof(frame));
    close(fd);
}

static void invalid_iovec(void) {
    struct msghdr msg;
    struct iovec iov;
    size_t page_len;
    void *fault = fault_page(&page_len);
    int rc;

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = fault;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    rc = sendmsg(-1, &msg, 0);
    out("sendmsg", "invalid_iovec", "rc=%d|errno=%s(%d)", rc,
        errno_name(rc < 0 ? errno : 0), rc < 0 ? errno : 0);
    if (fault != MAP_FAILED) munmap(fault, page_len);
}

static void udp_destination(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    struct iovec iov[2];
    struct msghdr msg;
    const char left[] = "send";
    const char right[] = "msg";
    int rc;

    if (fd < 0) {
        out("sendmsg", "udp_destination", "socket=%d:%s(%d)", fd,
            errno_name(errno), errno);
        return;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    memset(iov, 0, sizeof(iov));
    iov[0].iov_base = (void *)left;
    iov[0].iov_len = sizeof(left) - 1;
    iov[1].iov_base = (void *)right;
    iov[1].iov_len = sizeof(right) - 1;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    rc = (int)sendmsg(fd, &msg, MSG_DONTWAIT);
    out("sendmsg", "udp_destination", "rc=%d|errno=%s(%d)|iov=%zu",
        rc, errno_name(rc < 0 ? errno : 0), rc < 0 ? errno : 0,
        sizeof(left) + sizeof(right) - 2);
    close(fd);
}

void probe_sendmsg(void) {
    ordering_faults();
    invalid_iovec();
    udp_destination();
    packet_destination();
}
