// /bin/nc — minimal netcat. Two modes:
//   nc <host> <port>          TCP client
//   nc -l <port>              TCP listener (accepts one conn)
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static long parse_int(const char *s) {
    long v = 0; while (*s >= '0' && *s <= '9') { v = v*10 + (*s-'0'); s++; } return v;
}

static unsigned int parse_ip(const char *s) {
    unsigned int a[4] = {0}; int idx = 0;
    while (*s && idx < 4) {
        unsigned int v = 0;
        while (*s >= '0' && *s <= '9') { v = v*10 + (*s - '0'); s++; }
        a[idx++] = v;
        if (*s == '.') s++;
    }
    return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static void pipe_loop(int fd) {
    char buf[256];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        write(1, buf, n);
    }
}

int main(int argc, char** argv, char** envp) {
    (void)envp;
    if (argc < 3) {
        write(2, "nc: usage: nc <host> <port> | nc -l <port>\n", 43);
        return 1;
    }
    int listen_mode = strcmp(argv[1], "-l") == 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;

    if (listen_mode) {
        long port = parse_int(argv[2]);
        struct sockaddr_in a = { 0 };
        a.sin_family = AF_INET;
        a.sin_port = htons((unsigned short)port);
        a.sin_addr.s_addr = 0;
        if (bind(fd, (struct sockaddr*)&a, sizeof(a)) < 0) return 2;
        if (listen(fd, 1) < 0) return 3;
        int cfd = accept(fd, 0, 0);
        if (cfd < 0) return 4;
        pipe_loop(cfd);
        close(cfd);
    } else {
        long port = parse_int(argv[2]);
        unsigned int ip_host = parse_ip(argv[1]);
        struct sockaddr_in a = { 0 };
        a.sin_family = AF_INET;
        a.sin_port = htons((unsigned short)port);
        a.sin_addr.s_addr = htonl(ip_host);
        if (connect(fd, (struct sockaddr*)&a, sizeof(a)) < 0) {
            write(2, "nc: connect failed\n", 19);
            return 5;
        }
        pipe_loop(fd);
    }
    close(fd);
    return 0;
}
