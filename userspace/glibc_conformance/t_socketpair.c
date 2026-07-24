/* Linux row-53 socketpair(2) corpus; compared verbatim by N16. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Report a socketpair attempt; on success verify the pair is connected by a
   round-trip, then report the descriptor flags of fd[0]. */
static void mk(const char *label, int domain, int type, int protocol) {
    int sv[2] = { -1, -1 };
    errno = 0;
    int rc = socketpair(domain, type, protocol, sv);
    if (rc != 0) { printf("%s rc=-1 errno=%d\n", label, errno); return; }
    char out = 'x', in = 0;
    ssize_t w = write(sv[0], &out, 1);
    ssize_t n = read(sv[1], &in, 1);
    int fdflags = fcntl(sv[0], F_GETFD);
    int status = fcntl(sv[0], F_GETFL);
    printf("%s rc=0 roundtrip=%d cloexec=%d nonblock=%d\n", label,
        w == 1 && n == 1 && in == 'x',
        fdflags >= 0 && (fdflags & FD_CLOEXEC) ? 1 : 0,
        status >= 0 && (status & O_NONBLOCK) ? 1 : 0);
    close(sv[0]); close(sv[1]);
}

int main(void) {
    /* AF_UNIX supports stream, datagram, and seqpacket socketpairs. */
    mk("unix_stream", AF_UNIX, SOCK_STREAM, 0);
    mk("unix_dgram", AF_UNIX, SOCK_DGRAM, 0);
    mk("unix_seqpacket", AF_UNIX, SOCK_SEQPACKET, 0);
    /* unix_create maps SOCK_RAW onto the datagram personality. */
    mk("unix_raw", AF_UNIX, SOCK_RAW, 0);
    /* Flags are consumed by socketpair itself. */
    mk("unix_stream_cloexec", AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    mk("unix_stream_nonblock", AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);

    /* Protocol PF_UNIX(1) is accepted; other protocols are rejected. */
    mk("unix_proto_pf_unix", AF_UNIX, SOCK_STREAM, 1);
    mk("unix_proto_bad", AF_UNIX, SOCK_STREAM, 6);

    /* Every non-AF_UNIX family uses sock_no_socketpair -> EOPNOTSUPP. */
    mk("inet_stream", AF_INET, SOCK_STREAM, 0);
    mk("inet_dgram", AF_INET, SOCK_DGRAM, 0);
    mk("inet6_stream", AF_INET6, SOCK_STREAM, 0);

    /* Invalid type flag bits: EINVAL, before the family EOPNOTSUPP. */
    mk("bad_type_flag", AF_INET, SOCK_STREAM | 0x40000000, 0);
    /* Out-of-range type: EINVAL. */
    mk("bad_type", AF_UNIX, 99, 0);
    /* Unknown family with a valid type: EOPNOTSUPP (sock_no_socketpair after
       sock_create succeeds), or EAFNOSUPPORT if the family is unregistered. */
    mk("bad_family", 4242, SOCK_STREAM, 0);
    return 0;
}
