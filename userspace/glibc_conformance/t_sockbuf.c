/* Linux SO_RCVBUF/SO_SNDBUF doubling + minimum corpus; N17/N18. */
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static int roundtrip(int fd, int opt, int want) {
    int got = 0;
    socklen_t len = sizeof(got);
    setsockopt(fd, SOL_SOCKET, opt, &want, sizeof(want));
    getsockopt(fd, SOL_SOCKET, opt, &got, &len);
    return got;
}

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    /* Linux stores 2*val (metadata reservation); readback shows the double. */
    printf("rcvbuf_8192 doubled=%d\n", roundtrip(fd, SO_RCVBUF, 8192) == 16384);
    printf("sndbuf_8192 doubled=%d\n", roundtrip(fd, SO_SNDBUF, 8192) == 16384);
    printf("rcvbuf_10000 doubled=%d\n", roundtrip(fd, SO_RCVBUF, 10000) == 20000);
    /* Below the protocol minimum, the value floors at SOCK_MIN_*BUF. */
    printf("rcvbuf_min1=%d\n", roundtrip(fd, SO_RCVBUF, 1));
    printf("sndbuf_min1=%d\n", roundtrip(fd, SO_SNDBUF, 1));
    close(fd);
    return 0;
}
