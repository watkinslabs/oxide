// Tiny UDP echo server. Binds 0.0.0.0:7; echoes 4 datagrams.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { write(1, "udp_echo: socket failed\n", 24); return 1; }

    struct sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_port   = htons(7);
    a.sin_addr.s_addr = 0;
    if (bind(fd, (struct sockaddr*)&a, sizeof(a)) < 0) {
        write(1, "udp_echo: bind failed\n", 22);
        return 2;
    }
    write(1, "udp_echo: bound 0.0.0.0:7, looping\n", 35);

    char buf[256];
    for (int i = 0; i < 4; i++) {
        struct sockaddr_in src = { 0 };
        socklen_t slen = sizeof(src);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&src, &slen);
        if (n <= 0) break;
        sendto(fd, buf, n, 0, (struct sockaddr*)&src, sizeof(src));
    }
    return 0;
}
