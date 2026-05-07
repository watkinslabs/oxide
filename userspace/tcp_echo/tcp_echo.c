// Tiny TCP echo server. socket → bind → listen → accept → echo, then exit.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { write(1, "tcp_echo: socket failed\n", 24); return 1; }

    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_port   = htons(8);
    a.sin_addr.s_addr = 0;
    if (bind(fd, (struct sockaddr*)&a, sizeof(a)) < 0) {
        write(1, "tcp_echo: bind failed\n", 22); return 2;
    }
    if (listen(fd, 1) < 0) {
        write(1, "tcp_echo: listen failed\n", 24); return 3;
    }
    write(1, "tcp_echo: listening on 0.0.0.0:8\n", 33);

    int cfd = accept(fd, 0, 0);
    if (cfd < 0) { write(1, "tcp_echo: accept eagain\n", 24); return 4; }

    char buf[256];
    ssize_t n = read(cfd, buf, sizeof(buf));
    if (n > 0) write(cfd, buf, n);
    return 0;
}
