/* POSIX aio: aio_read/aio_write/aio_error/aio_return/aio_suspend/
   aio_fsync/aio_cancel/lio_listio vs host glibc. Deterministic output. */
#define _GNU_SOURCE
#include <aio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static const char DATA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

static int wait_done(struct aiocb *cb){
    int e;
    do { e = aio_error(cb); } while (e == EINPROGRESS);
    return e;
}

int main(void){
    char tmpl[] = "/tmp/oxide_aio_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0){ perror("mkstemp"); return 1; }

    /* seed the file with DATA via pwrite so aio_read has content */
    pwrite(fd, DATA, sizeof DATA - 1, 0);

    /* 1. aio_read a chunk at offset 4 */
    char rbuf[16]; memset(rbuf, 0, sizeof rbuf);
    struct aiocb r; memset(&r, 0, sizeof r);
    r.aio_fildes = fd;
    r.aio_buf = rbuf;
    r.aio_nbytes = 10;
    r.aio_offset = 4;
    r.aio_sigevent.sigev_notify = SIGEV_NONE;
    if (aio_read(&r)){ perror("aio_read"); return 1; }
    int e = wait_done(&r);
    ssize_t got = aio_return(&r);
    printf("read err=%d ret=%zd buf=%.10s\n", e, got, rbuf);

    /* 2. aio_write 6 bytes at offset 0, then aio_fsync */
    struct aiocb w; memset(&w, 0, sizeof w);
    const char *wd = "oxide!";
    w.aio_fildes = fd;
    w.aio_buf = (void*)wd;
    w.aio_nbytes = 6;
    w.aio_offset = 0;
    w.aio_sigevent.sigev_notify = SIGEV_NONE;
    if (aio_write(&w)){ perror("aio_write"); return 1; }
    e = wait_done(&w);
    printf("write err=%d ret=%zd\n", e, aio_return(&w));

    struct aiocb sy; memset(&sy, 0, sizeof sy);
    sy.aio_fildes = fd;
    sy.aio_sigevent.sigev_notify = SIGEV_NONE;
    if (aio_fsync(O_SYNC, &sy)){ perror("aio_fsync"); return 1; }
    e = wait_done(&sy);
    printf("fsync err=%d ret=%zd\n", e, aio_return(&sy));

    /* 3. aio_suspend on a single-element list */
    char sbuf[8]; memset(sbuf, 0, sizeof sbuf);
    struct aiocb s; memset(&s, 0, sizeof s);
    s.aio_fildes = fd;
    s.aio_buf = sbuf;
    s.aio_nbytes = 6;
    s.aio_offset = 0;
    s.aio_sigevent.sigev_notify = SIGEV_NONE;
    aio_read(&s);
    const struct aiocb *list[1] = { &s };
    aio_suspend(list, 1, NULL);
    printf("suspend err=%d ret=%zd buf=%.6s\n", aio_error(&s), aio_return(&s), sbuf);

    /* 4. lio_listio(LIO_WAIT) with 2 ops (a read + a write) */
    char l0[8]; memset(l0, 0, sizeof l0);
    const char *l1d = "ZZ";
    struct aiocb la, lb; memset(&la, 0, sizeof la); memset(&lb, 0, sizeof lb);
    la.aio_fildes = fd; la.aio_lio_opcode = LIO_READ;
    la.aio_buf = l0; la.aio_nbytes = 5; la.aio_offset = 0;
    la.aio_sigevent.sigev_notify = SIGEV_NONE;
    lb.aio_fildes = fd; lb.aio_lio_opcode = LIO_WRITE;
    lb.aio_buf = (void*)l1d; lb.aio_nbytes = 2; lb.aio_offset = 30;
    lb.aio_sigevent.sigev_notify = SIGEV_NONE;
    struct aiocb *llist[2] = { &la, &lb };
    int lr = lio_listio(LIO_WAIT, llist, 2, NULL);
    printf("lio rc=%d aerr=%d aret=%zd buf=%.5s berr=%d bret=%zd\n",
           lr, aio_error(&la), aio_return(&la), l0, aio_error(&lb), aio_return(&lb));

    /* 5. aio_cancel on a fresh request (result is AIO_*: NOTCANCELED or ALLDONE) */
    char cbuf[8]; memset(cbuf, 0, sizeof cbuf);
    struct aiocb c; memset(&c, 0, sizeof c);
    c.aio_fildes = fd;
    c.aio_buf = cbuf;
    c.aio_nbytes = 4;
    c.aio_offset = 0;
    c.aio_sigevent.sigev_notify = SIGEV_NONE;
    aio_read(&c);
    int cr = aio_cancel(fd, &c);
    printf("cancel in {CANCELED,NOTCANCELED,ALLDONE} = %d\n",
           cr == AIO_CANCELED || cr == AIO_NOTCANCELED || cr == AIO_ALLDONE);
    wait_done(&c);          /* let it finish before teardown */
    aio_return(&c);

    close(fd);
    unlink(tmpl);
    return 0;
}
