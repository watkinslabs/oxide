/* Linux TCP connect wait corpus; output is compared verbatim by N25. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

enum {
    LISTEN_BACKLOG = 1,
    LISTEN_QUEUE_SLACK = 1,
    FILL_CONNECTIONS = LISTEN_BACKLOG + LISTEN_QUEUE_SLACK,
    CONNECT_TIMEOUT_SECONDS = 1,
    POLL_TIMEOUT_MILLISECONDS = 1000,
    SEND_BUFFER_BYTES = 4096,
    IO_BUFFER_BYTES = 1024,
    FILL_WRITE_LIMIT = 1024,
    LINGER_ENABLE = 1,
    LINGER_RESET_SECONDS = 0,
    SOCKET_ERROR = -1,
};

static volatile sig_atomic_t signal_count;

static int loopback_listener(struct sockaddr_in *address) {
    const int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    socklen_t address_length = sizeof(*address);
    if (listener == SOCKET_ERROR) return SOCKET_ERROR;
    *address = (struct sockaddr_in) {
        .sin_family = AF_INET,
        .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
    };
    if (bind(listener, (const struct sockaddr *)address, address_length) == SOCKET_ERROR
        || listen(listener, LISTEN_BACKLOG) == SOCKET_ERROR
        || getsockname(listener, (struct sockaddr *)address, &address_length) == SOCKET_ERROR) {
        close(listener);
        return SOCKET_ERROR;
    }
    return listener;
}

static int connected_pair(int *client, int *server) {
    struct sockaddr_in address;
    const int listener = loopback_listener(&address);
    *client = SOCKET_ERROR;
    *server = SOCKET_ERROR;
    if (listener == SOCKET_ERROR) return SOCKET_ERROR;
    *client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*client != SOCKET_ERROR
        && connect(*client, (const struct sockaddr *)&address, sizeof(address)) != SOCKET_ERROR) {
        *server = accept(listener, NULL, NULL);
    }
    close(listener);
    if (*server != SOCKET_ERROR) return 0;
    if (*client != SOCKET_ERROR) close(*client);
    *client = SOCKET_ERROR;
    return SOCKET_ERROR;
}

static void close_pair(int client, int server) {
    if (client != SOCKET_ERROR) close(client);
    if (server != SOCKET_ERROR) close(server);
}

static void backlog_connect_timeout(void) {
    struct sockaddr_in address;
    const int listener = loopback_listener(&address);
    int filled[FILL_CONNECTIONS];
    const int waiting = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    const struct timeval timeout = { .tv_sec = CONNECT_TIMEOUT_SECONDS };
    size_t filled_count = 0;
    int setup_failed = listener == SOCKET_ERROR || waiting == SOCKET_ERROR;
    while (!setup_failed && filled_count < FILL_CONNECTIONS) {
        filled[filled_count] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (filled[filled_count] == SOCKET_ERROR
            || connect(filled[filled_count], (const struct sockaddr *)&address,
                sizeof(address)) == SOCKET_ERROR) {
            setup_failed = 1;
        } else {
            ++filled_count;
        }
    }
    if (setup_failed
        || setsockopt(waiting, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == SOCKET_ERROR) {
        puts("connect_timeout=setup_failed");
    } else {
        errno = 0;
        const int result = connect(waiting, (const struct sockaddr *)&address, sizeof(address));
        printf("connect_timeout rc=%d errno=%d\n", result, errno);
    }
    if (waiting != SOCKET_ERROR) close(waiting);
    while (filled_count != 0) close(filled[--filled_count]);
    if (listener != SOCKET_ERROR) close(listener);
}

static void alarm_handler(int signal_number) {
    (void)signal_number;
    ++signal_count;
}

static void backlog_connect_signal(void) {
    struct sockaddr_in address;
    const int listener = loopback_listener(&address);
    int filled[FILL_CONNECTIONS];
    const int waiting = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    const struct sigaction action = { .sa_handler = alarm_handler };
    struct sigaction previous;
    size_t filled_count = 0;
    int setup_failed = listener == SOCKET_ERROR || waiting == SOCKET_ERROR;
    while (!setup_failed && filled_count < FILL_CONNECTIONS) {
        filled[filled_count] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (filled[filled_count] == SOCKET_ERROR
            || connect(filled[filled_count], (const struct sockaddr *)&address,
                sizeof(address)) == SOCKET_ERROR) {
            setup_failed = 1;
        } else {
            ++filled_count;
        }
    }
    if (setup_failed || sigaction(SIGALRM, &action, &previous) == SOCKET_ERROR) {
        puts("connect_signal=setup_failed");
    } else {
        signal_count = 0;
        alarm(CONNECT_TIMEOUT_SECONDS);
        errno = 0;
        const int result = connect(waiting, (const struct sockaddr *)&address, sizeof(address));
        alarm(0);
        printf("connect_signal rc=%d errno=%d signals=%d\n", result, errno, (int)signal_count);
        sigaction(SIGALRM, &previous, NULL);
    }
    if (waiting != SOCKET_ERROR) close(waiting);
    while (filled_count != 0) close(filled[--filled_count]);
    if (listener != SOCKET_ERROR) close(listener);
}

static short socket_events(int fd) {
    struct pollfd event = { .fd = fd, .events = POLLIN | POLLOUT | POLLRDHUP };
    if (poll(&event, 1, POLL_TIMEOUT_MILLISECONDS) == SOCKET_ERROR) return SOCKET_ERROR;
    return event.revents;
}

static void reset_state(void) {
    int client, server;
    const struct linger reset = { .l_onoff = LINGER_ENABLE, .l_linger = LINGER_RESET_SECONDS };
    char byte;
    int first_error = 0, second_error = 0;
    socklen_t error_length = sizeof(first_error);
    if (connected_pair(&client, &server) == SOCKET_ERROR
        || setsockopt(server, SOL_SOCKET, SO_LINGER, &reset, sizeof(reset)) == SOCKET_ERROR) {
        puts("reset=setup_failed");
        close_pair(client, server);
        return;
    }
    close(server);
    const short events = socket_events(client);
    errno = 0;
    const int recv_result = recv(client, &byte, sizeof(byte), 0);
    const int recv_errno = errno;
    getsockopt(client, SOL_SOCKET, SO_ERROR, &first_error, &error_length);
    error_length = sizeof(second_error);
    getsockopt(client, SOL_SOCKET, SO_ERROR, &second_error, &error_length);
    errno = 0;
    const int write_result = send(client, &byte, sizeof(byte), MSG_NOSIGNAL);
    const int write_errno = errno;
    printf("reset events=%d recv=%d/%d error=%d,%d write=%d/%d\n", events,
        recv_result, recv_errno, first_error, second_error, write_result, write_errno);
    close(client);
}

static void fin_state(void) {
    int client, server;
    char byte;
    if (connected_pair(&client, &server) == SOCKET_ERROR || shutdown(server, SHUT_WR) == SOCKET_ERROR) {
        puts("fin=setup_failed");
        close_pair(client, server);
        return;
    }
    const short shutdown_events = socket_events(client);
    errno = 0;
    const int recv_result = recv(client, &byte, sizeof(byte), 0);
    const int recv_errno = errno;
    close(server);
    const short close_events = socket_events(client);
    printf("fin shutdown_events=%d recv=%d/%d close_events=%d\n", shutdown_events,
        recv_result, recv_errno, close_events);
    close(client);
}

static void ack_writable_state(void) {
    int client, server;
    char buffer[IO_BUFFER_BYTES];
    int flags, fill = 0;
    if (connected_pair(&client, &server) == SOCKET_ERROR
        || setsockopt(client, SOL_SOCKET, SO_SNDBUF, &(int){ SEND_BUFFER_BYTES }, sizeof(int)) == SOCKET_ERROR
        || (flags = fcntl(client, F_GETFL)) == SOCKET_ERROR
        || fcntl(client, F_SETFL, flags | O_NONBLOCK) == SOCKET_ERROR) {
        puts("ack_writable=setup_failed");
        close_pair(client, server);
        return;
    }
    memset(buffer, 0, sizeof(buffer));
    errno = 0;
    while (fill < FILL_WRITE_LIMIT && send(client, buffer, sizeof(buffer), MSG_NOSIGNAL) > 0) ++fill;
    const int fill_errno = errno;
    const int drained = recv(server, buffer, sizeof(buffer), 0);
    const short events = socket_events(client);
    errno = 0;
    const int resumed = send(client, buffer, sizeof(buffer), MSG_NOSIGNAL);
    const int resumed_errno = errno;
    printf("ack_writable fill_errno=%d drained=%d events=%d resumed=%d/%d\n", fill_errno,
        drained, events, resumed, resumed_errno);
    close_pair(client, server);
}

int main(void) {
    backlog_connect_timeout();
    backlog_connect_signal();
    ack_writable_state();
    reset_state();
    fin_state();
    return 0;
}
