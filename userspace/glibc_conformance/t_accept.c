/* Linux rows 43/288 accept/accept4 corpus; compared verbatim by N. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static void r(const char *label, int rc) {
    printf("%s rc=%d errno=%d\n", label, rc < 0 ? -1 : 0, rc < 0 ? errno : 0);
}

static int listener(struct sockaddr_in *addr) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    socklen_t len = sizeof(*addr);
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)addr, sizeof(*addr)) != 0
        || listen(fd, 4) != 0
        || getsockname(fd, (struct sockaddr *)addr, &len) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

static int connect_one(const struct sockaddr_in *addr) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0 || connect(fd, (const struct sockaddr *)addr, sizeof(*addr)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

static void *guard_pair(size_t page) {
    void *p = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED || mprotect((char *)p + page, page, PROT_NONE) != 0) {
        if (p != MAP_FAILED) munmap(p, page * 2);
        return MAP_FAILED;
    }
    return p;
}

static int next_client(const struct sockaddr_in *addr) {
    int fd = connect_one(addr);
    if (fd < 0) puts("connect=failed");
    return fd;
}

int main(void) {
    struct sockaddr_in addr;
    int l = listener(&addr);
    if (l < 0) { puts("setup=failed"); return 0; }

    /* accept4 with an invalid flag bit: Linux __sys_accept4_file rejects
       anything outside SOCK_CLOEXEC|SOCK_NONBLOCK with EINVAL, and this is
       checked before the blocking wait. */
    errno = 0; r("accept4_badflag", accept4(l, NULL, NULL, 0x40));

    /* accept on a non-listening (freshly created) socket: EINVAL. */
    int notlisten = socket(AF_INET, SOCK_STREAM, 0);
    errno = 0; r("accept_nonlisten", accept(notlisten, NULL, NULL));
    close(notlisten);

    /* accept on a UDP socket: EOPNOTSUPP (sock has no accept op). */
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    errno = 0; r("accept_udp", accept(udp, NULL, NULL));
    close(udp);

    /* Bad fd. */
    errno = 0; r("accept_badfd", accept(-1, NULL, NULL));

    /* fd lookup precedes accept4's flag screen; after a valid lookup the
       flag screen precedes socket classification. */
    errno = 0; r("accept4_badfd_badflag", accept4(-1, NULL, NULL, 0x40));
    int file = open("/dev/null", O_RDONLY);
    errno = 0; r("accept_file", accept(file, NULL, NULL));
    errno = 0; r("accept4_file_badflag", accept4(file, NULL, NULL, 0x40));
    close(file);

    /* A real connection: accept returns a fd; the accepted fd's CLOEXEC and
       NONBLOCK come only from accept4 flags, never inherited from the
       listener. Establish a client first. */
    int c = next_client(&addr);
    if (c < 0) { close(l); return 0; }
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int s = accept4(l, (struct sockaddr *)&peer, &plen, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (s < 0) { r("accept_conn", s); close(c); close(l); return 0; }
    int fdflags = fcntl(s, F_GETFD);
    int status = fcntl(s, F_GETFL);
    printf("accepted cloexec=%d nonblock=%d peer_family=%d peer_len=%u\n",
        fdflags >= 0 && (fdflags & FD_CLOEXEC) ? 1 : 0,
        status >= 0 && (status & O_NONBLOCK) ? 1 : 0,
        peer.sin_family, (unsigned)plen);

    /* A plain accept (no flags) yields a blocking, non-cloexec fd. */
    int c2 = next_client(&addr);
    if (c2 >= 0) {
        int s2 = accept(l, NULL, NULL);
        if (s2 >= 0) {
            int f2 = fcntl(s2, F_GETFD);
            int st2 = fcntl(s2, F_GETFL);
            printf("plain_accept cloexec=%d nonblock=%d\n",
                f2 >= 0 && (f2 & FD_CLOEXEC) ? 1 : 0,
                st2 >= 0 && (st2 & O_NONBLOCK) ? 1 : 0);
            close(s2);
        }
        close(c2);
    }

    /* A NULL peer-address pointer suppresses all addrlen access. */
    int c3 = next_client(&addr);
    if (c3 >= 0) {
        errno = 0;
        int s3 = accept(l, NULL, (socklen_t *)1);
        r("accept_null_addr_ignores_len", s3);
        if (s3 >= 0) close(s3);
        close(c3);
    }

    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *guard = guard_pair(page);
    void *ro_len = mmap(NULL, page, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *ro_addr = mmap(NULL, page, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guard == MAP_FAILED || ro_len == MAP_FAILED || ro_addr == MAP_FAILED) {
        puts("mmap=failed");
        close(s); close(c); close(l);
        return 0;
    }

    /* The accepted child is discarded on every copyout failure, so each case
       queues a fresh connection. */
    int cf = next_client(&addr);
    if (cf >= 0) {
        errno = 0; r("accept_null_len", accept(l, (struct sockaddr *)&peer, NULL));
        close(cf);
    }

    socklen_t *split_len = (socklen_t *)((char *)guard + page - 2);
    int cg = next_client(&addr);
    if (cg >= 0) {
        errno = 0; r("accept_split_len", accept(l, (struct sockaddr *)&peer, split_len));
        close(cg);
    }

    socklen_t *locked_len = (socklen_t *)ro_len;
    *locked_len = sizeof(peer);
    memset(&peer, 0xa5, sizeof(peer));
    mprotect(ro_len, page, PROT_READ);
    int crl = next_client(&addr);
    if (crl >= 0) {
        errno = 0;
        int rc = accept(l, (struct sockaddr *)&peer, locked_len);
        printf("accept_readonly_len rc=%d errno=%d peer_unchanged=%d\n",
            rc < 0 ? -1 : 0, rc < 0 ? errno : 0,
            ((unsigned char *)&peer)[0] == 0xa5);
        if (rc >= 0) close(rc);
        close(crl);
    }

    socklen_t zero = 0;
    int cz = next_client(&addr);
    if (cz >= 0) {
        errno = 0;
        int rc = accept(l, (struct sockaddr *)1, &zero);
        printf("accept_zero_len_bad_addr rc=%d errno=%d len=%u\n",
            rc < 0 ? -1 : 0, rc < 0 ? errno : 0, (unsigned)zero);
        if (rc >= 0) close(rc);
        close(cz);
    }

    socklen_t neg = (socklen_t)-1;
    int cn = next_client(&addr);
    if (cn >= 0) {
        errno = 0; r("accept_negative_len", accept(l, (struct sockaddr *)&peer, &neg));
        close(cn);
    }

    socklen_t ro_addr_len = sizeof(peer);
    mprotect(ro_addr, page, PROT_READ);
    int cra = next_client(&addr);
    if (cra >= 0) {
        errno = 0;
        int rc = accept(l, (struct sockaddr *)ro_addr, &ro_addr_len);
        printf("accept_readonly_addr rc=%d errno=%d len=%u\n",
            rc < 0 ? -1 : 0, rc < 0 ? errno : 0, (unsigned)ro_addr_len);
        if (rc >= 0) close(rc);
        close(cra);
    }

    struct sockaddr *split_addr = (struct sockaddr *)((char *)guard + page - 8);
    socklen_t split_addr_len = sizeof(peer);
    int cga = next_client(&addr);
    if (cga >= 0) {
        errno = 0;
        int rc = accept(l, split_addr, &split_addr_len);
        printf("accept_split_addr rc=%d errno=%d len=%u\n",
            rc < 0 ? -1 : 0, rc < 0 ? errno : 0, (unsigned)split_addr_len);
        if (rc >= 0) close(rc);
        close(cga);
    }

    munmap(guard, page * 2);
    munmap(ro_len, page);
    munmap(ro_addr, page);
    close(s); close(c); close(l);
    return 0;
}
