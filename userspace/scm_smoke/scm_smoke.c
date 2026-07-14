// /bin/scm_smoke — AF_UNIX SCM_RIGHTS + SCM_CREDENTIALS (phase 15).
// socketpair(AF_UNIX): parent sends, over a control message, BOTH an
// open fd (SCM_RIGHTS, the write end of a pipe) and — with SO_PASSCRED
// set on the receiver — its credentials (SCM_CREDENTIALS). The peer
// recvmsg()s, writes through the passed fd, and the parent reads the
// byte back through the pipe; the peer also checks the received
// (pid,uid,gid) tuple is sane.

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>

#ifndef AF_UNIX
#define AF_UNIX 1
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif
#ifndef SO_PASSCRED
#define SO_PASSCRED 16
#endif
#ifndef SCM_RIGHTS
#define SCM_RIGHTS 1
#endif
#ifndef SCM_CREDENTIALS
#define SCM_CREDENTIALS 2
#endif

struct ucred_x { unsigned int pid, uid, gid; };

#define PASS "scm_smoke: PASS\n"
static int fail(const char *why) {
    char b[96]; int n = snprintf(b, sizeof b, "scm_smoke: FAIL %s errno=%d\n", why, errno);
    write(1, b, n);
    return 1;
}

static int send_fds(int sock, const int *fds, size_t count) {
    char payload = 'f';
    struct iovec iov = { &payload, 1 };
    char control[CMSG_SPACE(2 * sizeof(int))];
    struct msghdr msg = {0};
    memset(control, 0, sizeof control);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = CMSG_SPACE(count * sizeof(int));
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(count * sizeof(int));
    memcpy(CMSG_DATA(cmsg), fds, count * sizeof(int));
    return sendmsg(sock, &msg, 0) == 1 ? 0 : -1;
}

static int test_cloexec(void) {
    int sv[2], pfd[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0 || pipe(pfd) < 0) return fail("cloexec setup");
    if (send_fds(sv[0], &pfd[1], 1) < 0) return fail("cloexec send");
    char byte, control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = { &byte, 1 };
    struct msghdr msg = {0};
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = control; msg.msg_controllen = sizeof control;
    if (recvmsg(sv[1], &msg, MSG_CMSG_CLOEXEC) != 1) return fail("cloexec recv");
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    int fd = -1;
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return fail("cloexec cmsg");
    memcpy(&fd, CMSG_DATA(cmsg), sizeof fd);
    int fdflags = fcntl(fd, F_GETFD);
    if (!(msg.msg_flags & MSG_CMSG_CLOEXEC) || fdflags < 0 || !(fdflags & FD_CLOEXEC)) return fail("cloexec flags");
    close(fd); close(pfd[0]); close(pfd[1]); close(sv[0]); close(sv[1]);
    return 0;
}

static int test_cred_exact_len(void) {
    int sv[2], one = 1;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return fail("cred-len socketpair");
    if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof one) < 0) return fail("cred-len passcred");
    if (write(sv[0], "c", 1) != 1) return fail("cred-len write");
    char byte;
    struct iovec iov = { &byte, 1 };
    union { char bytes[CMSG_LEN(sizeof(struct ucred_x))]; struct cmsghdr align; } control;
    struct msghdr msg = {0};
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = control.bytes; msg.msg_controllen = sizeof control.bytes;
    if (recvmsg(sv[1], &msg, 0) != 1) return fail("cred-len recv");
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_len != CMSG_LEN(sizeof(struct ucred_x)) || (msg.msg_flags & MSG_CTRUNC))
        return fail("cred-len result");
    close(sv[0]); close(sv[1]);
    return 0;
}

static int test_seqpacket_no_eor(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) return fail("seqpacket socketpair");
    if (write(sv[0], "s", 1) != 1) return fail("seqpacket write");
    char byte;
    struct iovec iov = { &byte, 1 };
    struct msghdr msg = {0};
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    if (recvmsg(sv[1], &msg, 0) != 1 || (msg.msg_flags & MSG_EOR)) return fail("seqpacket eor");
    close(sv[0]); close(sv[1]);
    return 0;
}

static int test_fault_keeps_fd_prefix(void) {
    int sv[2], a[2], b[2], fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0 || pipe(a) < 0 || pipe(b) < 0) return fail("fault setup");
    fds[0] = a[1]; fds[1] = b[1];
    if (send_fds(sv[0], fds, 2) < 0) return fail("fault send");
    long page = sysconf(_SC_PAGESIZE);
    char *map = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED || mprotect(map + page, page, PROT_NONE) < 0) return fail("fault map");
    char *control = map + page - 20;
    char byte;
    struct iovec iov = { &byte, 1 };
    struct msghdr msg = {0};
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = control; msg.msg_controllen = CMSG_SPACE(2 * sizeof(int));
    if (recvmsg(sv[1], &msg, 0) != 1) return fail("fault recv");
    int fd = -1;
    memcpy(&fd, control + CMSG_LEN(0), sizeof fd);
    if (fd < 0 || fcntl(fd, F_GETFD) < 0 || !(msg.msg_flags & MSG_CTRUNC)) return fail("fault prefix");
    if (write(fd, "P", 1) != 1) return fail("fault fd write");
    char got;
    if (read(a[0], &got, 1) != 1 || got != 'P') return fail("fault fd identity");
    int reused = open("/dev/null", O_RDONLY);
    if (reused != fd + 1) return fail("fault fd rollback");
    mprotect(map + page, page, PROT_READ | PROT_WRITE);
    munmap(map, (size_t)page * 2);
    close(reused); close(fd); close(a[0]); close(a[1]); close(b[0]); close(b[1]); close(sv[0]); close(sv[1]);
    return 0;
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return fail("socketpair");

    int one = 1;
    // Receiver opts into credential passing.
    setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof one);

    // SO_PEERCRED: both ends of a socketpair belong to this process, so
    // the reported peer pid/uid/gid must be our own (real creds, not 0).
#ifndef SO_PEERCRED
#define SO_PEERCRED 17
#endif
    {
        struct ucred pc; socklen_t pl = sizeof pc;
        if (getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, &pc, &pl) < 0)
            return fail("getsockopt SO_PEERCRED");
        if (pc.pid != getpid() || pc.uid != getuid()) {
            char b[96];
            int n = snprintf(b, sizeof b, "scm_smoke: FAIL peercred pid=%d/%d uid=%u/%u\n",
                             pc.pid, getpid(), pc.uid, getuid());
            write(1, b, n);
            return 1;
        }
    }

    int pfd[2];
    if (pipe(pfd) < 0) return fail("pipe");

    // --- Sender: send SCM_RIGHTS (pfd[1]) over sv[0]. ---
    char iobuf[1] = { 'x' };
    struct iovec iov = { iobuf, 1 };
    union {
        char buf[256];
        struct cmsghdr align;
    } cu;
    memset(&cu, 0, sizeof cu);

    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cu.buf;
    mh.msg_controllen = CMSG_SPACE(sizeof(int));

    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type  = SCM_RIGHTS;
    c->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &pfd[1], sizeof(int));

    if (sendmsg(sv[0], &mh, 0) < 0) return fail("sendmsg");

    // --- Receiver: pull the fd + credentials. ---
    char rbuf[1];
    struct iovec riov = { rbuf, 1 };
    union { char buf[256]; struct cmsghdr align; } rc;
    memset(&rc, 0, sizeof rc);
    struct msghdr rmh;
    memset(&rmh, 0, sizeof rmh);
    rmh.msg_iov = &riov;
    rmh.msg_iovlen = 1;
    rmh.msg_control = rc.buf;
    rmh.msg_controllen = sizeof rc.buf;

    if (recvmsg(sv[1], &rmh, 0) < 0) return fail("recvmsg");

    int got_fd = -1, got_cred = 0;
    struct ucred_x cred = {0,0,0};
    for (struct cmsghdr *m = CMSG_FIRSTHDR(&rmh); m; m = CMSG_NXTHDR(&rmh, m)) {
        if (m->cmsg_level == SOL_SOCKET && m->cmsg_type == SCM_RIGHTS)
            memcpy(&got_fd, CMSG_DATA(m), sizeof(int));
        else if (m->cmsg_level == SOL_SOCKET && m->cmsg_type == SCM_CREDENTIALS) {
            memcpy(&cred, CMSG_DATA(m), sizeof cred);
            got_cred = 1;
        }
    }

    if (got_fd < 0) return fail("no-fd");

    // Prove the passed fd is the live pipe write end: write through it,
    // read it back from the original read end.
    if (write(got_fd, "Z", 1) != 1) return fail("write-passed-fd");
    char z;
    if (read(pfd[0], &z, 1) != 1 || z != 'Z') return fail("pipe-readback");

    // SO_PASSCRED was set on the receiver, so SCM_CREDENTIALS must be
    // delivered carrying the sender's real {pid,uid,gid} (this process's).
    if (!got_cred) return fail("no-cred");
    if (cred.pid != (unsigned)getpid() || cred.uid != (unsigned)getuid())
        return fail("cred-mismatch");

    if (test_cloexec() || test_cred_exact_len() || test_seqpacket_no_eor() || test_fault_keeps_fd_prefix()) return 1;

    write(1, PASS, sizeof(PASS) - 1);
    return 0;
}
