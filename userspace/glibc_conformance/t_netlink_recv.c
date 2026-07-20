/* Linux NETLINK_ROUTE receive/error corpus; output is compared verbatim by N27. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int open_route_socket(void) {
    struct sockaddr_nl local = { .nl_family = AF_NETLINK };
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0 || bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

enum { PIPE_READ_END, PIPE_WRITE_END };

struct blocked_receive {
    int fd;
    int started_fd;
    ssize_t received;
    unsigned short type;
    int saved_errno;
};

static void *blocking_recv(void *arg) {
    char bytes[NLMSG_SPACE(sizeof(struct ifinfomsg))];
    struct blocked_receive *state = arg;
    char started = '\0';
    (void)write(state->started_fd, &started, sizeof(started));
    errno = 0;
    state->received = recv(state->fd, bytes, sizeof(bytes), 0);
    state->saved_errno = errno;
    if (state->received >= (ssize_t)sizeof(struct nlmsghdr)) {
        state->type = ((struct nlmsghdr *)bytes)->nlmsg_type;
    } else {
        state->type = NLMSG_NOOP;
    }
    return NULL;
}

static int send_request(int fd, unsigned short type, unsigned short flags,
    unsigned int sequence) {
    struct {
        struct nlmsghdr header;
        struct ifinfomsg link;
    } request = {
        .header = {
            .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
            .nlmsg_type = type,
            .nlmsg_flags = flags,
            .nlmsg_seq = sequence,
        },
        .link = { .ifi_family = AF_UNSPEC },
    };
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    return sendto(fd, &request, request.header.nlmsg_len, 0,
        (struct sockaddr *)&kernel, sizeof(kernel));
}

static void getlink_readiness(void) {
    char bytes[NLMSG_SPACE(sizeof(struct ifinfomsg))];
    struct pollfd ready = { .events = POLLIN };
    int fd = open_route_socket();
    if (fd < 0 || send_request(fd, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP,
            NLMSG_MIN_TYPE) < 0) {
        puts("getlink=setup_failed");
        if (fd >= 0) close(fd);
        return;
    }
    ready.fd = fd;
    errno = 0;
    int poll_rc = poll(&ready, 1, -1);
    errno = 0;
    ssize_t got = recv(fd, bytes, sizeof(bytes), 0);
    struct nlmsghdr *header = got >= (ssize_t)sizeof(*header)
        ? (struct nlmsghdr *)bytes : NULL;
    printf("getlink poll=%d revents=%hd recv=%zd type=%hu errno=%d\n", poll_rc,
        ready.revents, got, header == NULL ? NLMSG_NOOP : header->nlmsg_type, errno);
    close(fd);
}

static void unsupported_request_error(void) {
    char bytes[NLMSG_SPACE(sizeof(struct nlmsgerr))];
    int fd = open_route_socket();
    if (fd < 0 || send_request(fd, RTM_MAX + 1, NLM_F_REQUEST | NLM_F_ACK,
            NLMSG_MIN_TYPE) < 0) {
        puts("unsupported=setup_failed");
        if (fd >= 0) close(fd);
        return;
    }
    errno = 0;
    ssize_t got = recv(fd, bytes, sizeof(bytes), 0);
    struct nlmsghdr *header = got >= (ssize_t)sizeof(*header)
        ? (struct nlmsghdr *)bytes : NULL;
    struct nlmsgerr *error = header != NULL && header->nlmsg_type == NLMSG_ERROR
        ? (struct nlmsgerr *)NLMSG_DATA(header) : NULL;
    printf("unsupported recv=%zd type=%hu error=%d errno=%d\n", got,
        header == NULL ? NLMSG_NOOP : header->nlmsg_type,
        error == NULL ? 0 : error->error, errno);
    close(fd);
}

static void blocked_receive_wake(void) {
    int started[PIPE_WRITE_END + 1];
    int fd = open_route_socket();
    pthread_t thread;
    struct blocked_receive state = { .fd = fd, .started_fd = -1 };
    char marker;
    if (fd < 0 || pipe(started) != 0) {
        puts("blocked=setup_failed");
        if (fd >= 0) close(fd);
        return;
    }
    state.started_fd = started[PIPE_WRITE_END];
    if (pthread_create(&thread, NULL, blocking_recv, &state) != 0
        || read(started[PIPE_READ_END], &marker, sizeof(marker)) != sizeof(marker)
        || send_request(fd, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP,
            NLMSG_MIN_TYPE) < 0
        || pthread_join(thread, NULL) != 0) {
        puts("blocked=execution_failed");
    } else {
        printf("blocked recv=%zd type=%hu errno=%d\n", state.received,
            state.type, state.saved_errno);
    }
    close(started[PIPE_READ_END]);
    close(started[PIPE_WRITE_END]);
    close(fd);
}

int main(void) {
    getlink_readiness();
    unsupported_request_error();
    blocked_receive_wake();
    return 0;
}
