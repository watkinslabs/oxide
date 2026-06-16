/* sendmmsg/recvmmsg over an AF_UNIX datagram socketpair. vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) { printf("nopair\n"); return 0; }
    char *m0 = "hello", *m1 = "world";
    struct iovec iv[2] = { { m0, 5 }, { m1, 5 } };
    struct mmsghdr out[2];
    memset(out, 0, sizeof out);
    out[0].msg_hdr.msg_iov = &iv[0]; out[0].msg_hdr.msg_iovlen = 1;
    out[1].msg_hdr.msg_iov = &iv[1]; out[1].msg_hdr.msg_iovlen = 1;
    int sent = sendmmsg(sv[0], out, 2, 0);

    char b0[8] = {0}, b1[8] = {0};
    struct iovec riv[2] = { { b0, 8 }, { b1, 8 } };
    struct mmsghdr in[2];
    memset(in, 0, sizeof in);
    in[0].msg_hdr.msg_iov = &riv[0]; in[0].msg_hdr.msg_iovlen = 1;
    in[1].msg_hdr.msg_iov = &riv[1]; in[1].msg_hdr.msg_iovlen = 1;
    int got = recvmmsg(sv[1], in, 2, 0, NULL);
    printf("sent=%d got=%d len0=%u len1=%u\n", sent, got, in[0].msg_len, in[1].msg_len);
    printf("data=%d %d\n", memcmp(b0, "hello", 5) == 0, memcmp(b1, "world", 5) == 0);
    return 0;
}
