/* AF_UNIX stream teardown: peer close wakes epoll and exposes EOF. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

enum { EPOLL_WAIT_TIMEOUT_MS = 100 };

int main(void) {
    int pair[2] = {-1, -1};
    struct epoll_event interest;
    struct epoll_event observed;
    char byte;
    int epfd;
    int close_rc;
    int result;
    int ready;
    ssize_t read_rc;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
        printf("socketpair=%d errno=%d\n", -1, errno);
        return 1;
    }
    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        printf("epoll_create1=%d errno=%d\n", epfd, errno);
        return 1;
    }
    memset(&interest, 0, sizeof(interest));
    interest.events = EPOLLIN | EPOLLRDHUP;
    interest.data.fd = pair[0];
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, pair[0], &interest) != 0) {
        printf("epoll_ctl=%d errno=%d\n", -1, errno);
        return 1;
    }
    close_rc = close(pair[1]);
    memset(&observed, 0, sizeof(observed));
    ready = epoll_wait(epfd, &observed, 1, EPOLL_WAIT_TIMEOUT_MS);
    read_rc = read(pair[0], &byte, sizeof(byte));
    printf("close=%d ready=%d in=%d hup=%d rdhup=%d read=%ld errno=%d\n",
           close_rc, ready, (observed.events & EPOLLIN) != 0,
           (observed.events & EPOLLHUP) != 0,
           (observed.events & EPOLLRDHUP) != 0, (long)read_rc,
           read_rc < 0 ? errno : 0);
    result = close_rc != 0 || ready != 1 || read_rc != 0;
    close(pair[0]);
    close(epfd);
    return result;
}
