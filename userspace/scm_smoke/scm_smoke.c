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

    write(1, PASS, sizeof(PASS) - 1);
    return 0;
}
