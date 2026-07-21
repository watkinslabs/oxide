#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
    TEST_BACKLOG = 1,
    TEST_CONNECT_TIMEOUT_MS = 1000,
    TEST_REFUSED_PORT = 23451,
    TEST_SUCCESS_PORT = 23452,
    TEST_WRITE_BYTE = 'x',
};

static void out(const char *case_name, int rc, int error, int detail) {
    printf("tcp_wait|%s|rc=%d|errno=%d|detail=%d\n", case_name, rc, error, detail);
}

static int open_tcp(void) {
    return socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
}

static void loopback_addr(struct sockaddr_in *addr, unsigned short port) {
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr->sin_port = htons(port);
}

static int listener(unsigned short port) {
    struct sockaddr_in addr;
    int fd = open_tcp();
    if (fd < 0) return -1;
    loopback_addr(&addr, port);
    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, TEST_BACKLOG) < 0) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

static void successful_connect_case(void) {
    struct sockaddr_in addr;
    int ready[2];
    int child_status = 0;
    int fd;
    pid_t child;
    if (pipe2(ready, O_CLOEXEC) < 0) { out("connect_accept", -1, errno, 0); return; }
    child = fork();
    if (child == 0) {
        int server = listener(TEST_SUCCESS_PORT);
        char marker = 'r';
        if (server < 0 || write(ready[1], &marker, sizeof(marker)) != sizeof(marker)) _exit(EXIT_FAILURE);
        int accepted = accept4(server, NULL, NULL, SOCK_CLOEXEC);
        if (accepted >= 0) close(accepted);
        close(server);
        _exit(accepted < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
    }
    close(ready[1]);
    char marker = 0;
    if (child < 0 || read(ready[0], &marker, sizeof(marker)) != sizeof(marker)) {
        out("connect_accept", -1, child < 0 ? errno : EIO, 0);
        close(ready[0]);
        return;
    }
    close(ready[0]);
    fd = open_tcp();
    loopback_addr(&addr, TEST_SUCCESS_PORT);
    int rc = fd < 0 ? -1 : connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    int error = rc < 0 ? errno : 0;
    if (fd >= 0) close(fd);
    if (waitpid(child, &child_status, 0) < 0) { out("connect_accept", -1, errno, 0); return; }
    out("connect_accept", rc, error, WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1);
}

static void refused_nonblocking_case(void) {
    struct sockaddr_in addr;
    struct pollfd wait_fd;
    socklen_t error_len = sizeof(int);
    int so_error = 0;
    int fd = open_tcp();
    if (fd < 0) { out("refused_nonblock", -1, errno, 0); return; }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        int error = errno;
        close(fd);
        out("refused_nonblock", -1, error, 0);
        return;
    }
    loopback_addr(&addr, TEST_REFUSED_PORT);
    int rc = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    int error = rc < 0 ? errno : 0;
    wait_fd = (struct pollfd) { .fd = fd, .events = POLLOUT | POLLERR, .revents = 0 };
    int waited = poll(&wait_fd, 1, TEST_CONNECT_TIMEOUT_MS);
    if (waited >= 0 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &error_len) < 0) so_error = -errno;
    close(fd);
    out("refused_nonblock", rc, error, waited == 0 ? 0 : so_error);
}

static void write_after_close_case(void) {
    struct sockaddr_in addr;
    int ready[2];
    int child_status = 0;
    int fd;
    pid_t child;
    if (pipe2(ready, O_CLOEXEC) < 0) { out("write_after_close", -1, errno, 0); return; }
    child = fork();
    if (child == 0) {
        int server = listener(TEST_SUCCESS_PORT);
        int accepted = server < 0 ? -1 : accept4(server, NULL, NULL, SOCK_CLOEXEC);
        char marker = 'c';
        if (accepted < 0 || write(ready[1], &marker, sizeof(marker)) != sizeof(marker)) _exit(EXIT_FAILURE);
        close(accepted);
        close(server);
        _exit(EXIT_SUCCESS);
    }
    close(ready[1]);
    fd = open_tcp();
    loopback_addr(&addr, TEST_SUCCESS_PORT);
    if (child < 0 || fd < 0 || connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int error = child < 0 || fd < 0 ? errno : errno;
        if (fd >= 0) close(fd);
        out("write_after_close", -1, error, 0);
        return;
    }
    char marker = 0;
    if (read(ready[0], &marker, sizeof(marker)) != sizeof(marker)) { out("write_after_close", -1, errno, 0); close(fd); return; }
    close(ready[0]);
    char peer_byte = 0;
    ssize_t eof = read(fd, &peer_byte, sizeof(peer_byte));
    if (eof != 0) {
        out("write_after_close", -1, eof < 0 ? errno : EIO, (int)eof);
        close(fd);
        return;
    }
    signal(SIGPIPE, SIG_IGN);
    ssize_t rc = write(fd, &(char){ TEST_WRITE_BYTE }, sizeof(char));
    int error = rc < 0 ? errno : 0;
    close(fd);
    if (waitpid(child, &child_status, 0) < 0) { out("write_after_close", -1, errno, 0); return; }
    out("write_after_close", (int)rc, error, WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    successful_connect_case();
    refused_nonblocking_case();
    write_after_close_case();
    puts("tcp_wait|complete|status=DONE");
    return EXIT_SUCCESS;
}
