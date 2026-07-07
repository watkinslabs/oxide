/* /bin/aio_probe — end-to-end Linux libaio round-trip smoke.
 *
 * Proves userspace can actually USE libaio's raw syscalls: io_setup(2)
 * registers a context, io_submit(2) runs one IOCB_CMD_PREAD inline and
 * queues its completion, io_getevents(2) copies the completion back, and
 * the read bytes match the file content. The oxide model completes each
 * iocb synchronously at submit, so getevents returns immediately.
 *
 * Raw syscalls (the x86 cross-musl sysroot has no <linux/aio_abi.h>, so the
 * iocb / io_event structs are defined inline). Slot numbers are arch-common
 * on x86_64 and aarch64: io_setup=206, io_submit=209, io_getevents=208,
 * io_destroy=207. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

#define NR_IO_SETUP     206
#define NR_IO_DESTROY   207
#define NR_IO_GETEVENTS 208
#define NR_IO_SUBMIT    209

#define IOCB_CMD_PREAD  0

/* struct iocb — 64 bytes, Linux aio_abi.h layout. */
struct iocb {
    uint64_t aio_data;
    uint32_t aio_key;
    uint32_t aio_rw_flags;
    uint16_t aio_lio_opcode;
    int16_t  aio_reqprio;
    uint32_t aio_fildes;
    uint64_t aio_buf;
    uint64_t aio_nbytes;
    int64_t  aio_offset;
    uint64_t aio_reserved2;
    uint32_t aio_flags;
    uint32_t aio_resfd;
};

/* struct io_event — 32 bytes. */
struct io_event {
    uint64_t data;
    uint64_t obj;
    int64_t  res;
    int64_t  res2;
};

int main(void) {
    /* Write a known payload to a scratch file, then aio-read it back. */
    const char *path = "/tmp/aio_probe.dat";
    const char payload[] = "AIODATA0";       /* 8 bytes, no NUL read-back */
    int wfd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (wfd < 0) { printf("aio_probe: open-w FAIL\n"); return 1; }
    if (write(wfd, payload, 8) != 8) { printf("aio_probe: write FAIL\n"); return 1; }
    close(wfd);

    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("aio_probe: open-r FAIL\n"); return 1; }

    unsigned long ctx = 0;                    /* MUST be zero on entry */
    long rc = syscall(NR_IO_SETUP, 8u, &ctx);
    if (rc != 0) { printf("aio_probe: io_setup FAIL rc=%ld\n", rc); return 1; }

    char buf[8];
    memset(buf, 0, sizeof buf);
    struct iocb cb;
    memset(&cb, 0, sizeof cb);
    cb.aio_data       = 0xABCDu;
    cb.aio_lio_opcode = IOCB_CMD_PREAD;
    cb.aio_fildes     = (uint32_t)fd;
    cb.aio_buf        = (uint64_t)(uintptr_t)buf;
    cb.aio_nbytes     = 8;
    cb.aio_offset     = 0;

    struct iocb *cbp = &cb;
    rc = syscall(NR_IO_SUBMIT, ctx, (long)1, &cbp);
    if (rc != 1) { printf("aio_probe: io_submit FAIL rc=%ld\n", rc); return 1; }

    struct io_event ev;
    memset(&ev, 0, sizeof ev);
    rc = syscall(NR_IO_GETEVENTS, ctx, (long)1, (long)1, &ev, (void *)0);
    if (rc != 1) { printf("aio_probe: io_getevents FAIL rc=%ld\n", rc); return 1; }

    if (ev.data != 0xABCDu) { printf("aio_probe: bad data=%llx\n", (unsigned long long)ev.data); return 1; }
    if (ev.res != 8) { printf("aio_probe: bad res=%lld\n", (long long)ev.res); return 1; }
    if (memcmp(buf, payload, 8) != 0) { printf("aio_probe: content mismatch\n"); return 1; }

    (void)syscall(NR_IO_DESTROY, ctx);
    printf("aio_probe: PASS\n");
    return 0;
}
