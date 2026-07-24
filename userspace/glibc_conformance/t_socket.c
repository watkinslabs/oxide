/* Linux row-41 `socket(2)` corpus; output is compared verbatim by N29/N22. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

enum {
    BAD_FAMILY = 4242,      /* >= AF_MAX: Linux __sock_create -> EAFNOSUPPORT */
    UNREGISTERED_FAMILY = 4, /* AF_IPX: inside AF_MAX, no registered family */
    BAD_TYPE = 99,          /* stray flag bits: Linux __sys_socket -> EINVAL */
    TYPE_OVER_SOCK_MAX = 11, /* == SOCK_MAX, no flag bits set -> EINVAL */
    BAD_TYPE_FLAG = 0x10000000, /* outside SOCK_TYPE_MASK|CLOEXEC|NONBLOCK */
    BAD_NL_PROTO = 99,      /* no netlink family registered -> EPROTONOSUPPORT */
    UNIX_PROTO_PF_UNIX = 1, /* Linux unix_create accepts protocol == PF_UNIX */
};

/* Report a creation attempt without printing an fd value: a raw descriptor
   number is process-state dependent, while success/errno is the ABI. */
static void mk(const char *label, int family, int type, int protocol) {
    errno = 0;
    int fd = socket(family, type, protocol);
    int err = errno;
    printf("%s rc=%d errno=%d\n", label, fd < 0 ? -1 : 0, fd < 0 ? err : 0);
    if (fd >= 0) close(fd);
}

/* SO_DOMAIN/SO_TYPE/SO_PROTOCOL are the kernel's own record of the triple the
   socket was created with; they must echo the request, not a normalized form. */
static void triple(const char *label, int family, int type, int protocol) {
    int fd = socket(family, type, protocol);
    int dom = -1, typ = -1, prot = -1;
    socklen_t len = sizeof(int);
    if (fd < 0) { printf("%s triple=create_failed errno=%d\n", label, errno); return; }
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &dom, &len) != 0) dom = -1;
    len = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &typ, &len) != 0) typ = -1;
    len = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &prot, &len) != 0) prot = -1;
    printf("%s domain=%d type=%d protocol=%d\n", label, dom, typ, prot);
    close(fd);
}

/* SOCK_CLOEXEC and SOCK_NONBLOCK are consumed by socket(2) itself and must be
   observable through the descriptor and file-status flags. */
static void flags(const char *label, int type) {
    int fd = socket(AF_UNIX, type, 0);
    int fd_flags, status;
    if (fd < 0) { printf("%s flags=create_failed errno=%d\n", label, errno); return; }
    fd_flags = fcntl(fd, F_GETFD);
    status = fcntl(fd, F_GETFL);
    printf("%s cloexec=%d nonblock=%d\n", label,
        fd_flags >= 0 && (fd_flags & FD_CLOEXEC) ? 1 : 0,
        status >= 0 && (status & O_NONBLOCK) ? 1 : 0);
    close(fd);
}

/* Linux publishes the lowest free descriptor; a closed slot must be reused. */
static void publication(void) {
    int first = socket(AF_UNIX, SOCK_STREAM, 0);
    int second;
    if (first < 0) { printf("publication=create_failed errno=%d\n", errno); return; }
    close(first);
    second = socket(AF_UNIX, SOCK_STREAM, 0);
    printf("publication reuse=%d\n", second == first ? 1 : 0);
    if (second >= 0) close(second);
}

int main(void) {
    mk("unix_stream", AF_UNIX, SOCK_STREAM, 0);
    mk("unix_dgram", AF_UNIX, SOCK_DGRAM, 0);
    mk("unix_seqpacket", AF_UNIX, SOCK_SEQPACKET, 0);
    /* Linux unix_create maps SOCK_RAW onto the datagram personality. */
    mk("unix_raw", AF_UNIX, SOCK_RAW, 0);
    /* unix_create rejects every protocol except 0 and PF_UNIX. */
    mk("unix_proto_pf_unix", AF_UNIX, SOCK_STREAM, UNIX_PROTO_PF_UNIX);
    mk("unix_proto_bad", AF_UNIX, SOCK_STREAM, IPPROTO_TCP);

    mk("inet_stream", AF_INET, SOCK_STREAM, 0);
    mk("inet_stream_tcp", AF_INET, SOCK_STREAM, IPPROTO_TCP);
    mk("inet_dgram", AF_INET, SOCK_DGRAM, 0);
    mk("inet_dgram_udp", AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    /* inet_create matches (type, protocol) against its protocol list. */
    mk("inet_stream_udp", AF_INET, SOCK_STREAM, IPPROTO_UDP);
    mk("inet_dgram_tcp", AF_INET, SOCK_DGRAM, IPPROTO_TCP);
    /* SOCK_RAW requires CAP_NET_RAW in the owning user namespace. */
    mk("inet_raw_unpriv", AF_INET, SOCK_RAW, IPPROTO_ICMP);

    mk("inet6_stream", AF_INET6, SOCK_STREAM, 0);
    mk("inet6_dgram", AF_INET6, SOCK_DGRAM, 0);
    mk("inet6_raw_unpriv", AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    mk("netlink_route", AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    mk("netlink_route_dgram", AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    mk("netlink_route_stream", AF_NETLINK, SOCK_STREAM, NETLINK_ROUTE);
    mk("netlink_bad_proto", AF_NETLINK, SOCK_RAW, BAD_NL_PROTO);

    mk("bad_family", BAD_FAMILY, SOCK_STREAM, 0);
    mk("bad_type", AF_INET, BAD_TYPE, 0);
    mk("bad_type_flag", AF_INET, SOCK_STREAM | BAD_TYPE_FLAG, 0);
    mk("bad_family_neg", -1, SOCK_STREAM, 0);
    mk("bad_type_neg", AF_INET, -1, 0);
    /* __sys_socket screens the flag bits before __sock_create sees the family,
       so an invalid flag outranks an unsupported family. */
    mk("bad_flag_before_family", BAD_FAMILY, SOCK_STREAM | BAD_TYPE_FLAG, 0);
    /* __sock_create rejects family >= AF_MAX before it range-checks the type. */
    mk("bad_family_before_type", BAD_FAMILY, TYPE_OVER_SOCK_MAX, 0);
    /* An in-range but unregistered family is rejected only after the type
       range check, so a bad type outranks it. */
    mk("bad_type_before_unreg_family", UNREGISTERED_FAMILY, TYPE_OVER_SOCK_MAX, 0);
    mk("unreg_family", UNREGISTERED_FAMILY, SOCK_STREAM, 0);
    mk("type_over_sock_max", AF_INET, TYPE_OVER_SOCK_MAX, 0);

    triple("unix_stream", AF_UNIX, SOCK_STREAM, 0);
    /* unix_create rewrites sock->type, so SO_TYPE reports the datagram
       personality rather than the requested SOCK_RAW. */
    triple("unix_raw", AF_UNIX, SOCK_RAW, 0);
    triple("unix_seqpacket", AF_UNIX, SOCK_SEQPACKET, 0);
    triple("unix_proto_pf_unix", AF_UNIX, SOCK_STREAM, UNIX_PROTO_PF_UNIX);
    triple("inet_stream", AF_INET, SOCK_STREAM, 0);
    triple("inet_dgram_udp", AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    triple("inet6_dgram", AF_INET6, SOCK_DGRAM, 0);
    triple("netlink_route", AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    flags("plain", SOCK_STREAM);
    flags("cloexec", SOCK_STREAM | SOCK_CLOEXEC);
    flags("nonblock", SOCK_STREAM | SOCK_NONBLOCK);
    flags("both", SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK);

    publication();
    return 0;
}
