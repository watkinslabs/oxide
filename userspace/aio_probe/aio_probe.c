/* /bin/aio_probe — end-to-end Linux libaio round-trip smoke.
 *
 * Proves userspace can actually USE libaio's raw syscalls:
 *   - io_setup(2) returns the ADDRESS the completion ring is mapped at, and
 *     that mapping carries a valid `struct aio_ring` header (magic, nr,
 *     header_length, compat_features). libaio dereferences the context to
 *     reap without a syscall, so a cookie that is not a pointer breaks it.
 *   - io_submit(2) runs an IOCB_CMD_PREAD and publishes the completion into
 *     the ring, advancing the shared `tail`.
 *   - the completion is readable straight out of the mapping.
 *   - io_getevents(2) copies it back and advances the shared `head`.
 *   - io_setup rejects a non-zero *ctxp with EINVAL.
 *   - io_submit rejects a reserved field and an unknown opcode with EINVAL.
 *   - io_cancel answers EINVAL for an already-complete request, and
 *     EINPROGRESS for an outstanding IOCB_CMD_POLL.
 *
 * Raw syscalls (the x86 cross-musl sysroot has no <linux/aio_abi.h>, so the
 * iocb / io_event / aio_ring structs are defined inline). Slot numbers are
 * arch-common on x86_64 and aarch64: io_setup=206, io_destroy=207,
 * io_getevents=208, io_submit=209, io_cancel=210. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <sys/syscall.h>

#define NR_IO_SETUP     206
#define NR_IO_DESTROY   207
#define NR_IO_GETEVENTS 208
#define NR_IO_SUBMIT    209
#define NR_IO_CANCEL    210

#define IOCB_CMD_PREAD  0
#define IOCB_CMD_POLL   5
#define IOCB_CMD_NOOP   6

#define AIO_RING_MAGIC  0xa10a10a1u

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

/* struct aio_ring — 32-byte header, then the io_event array. */
struct aio_ring {
    unsigned id, nr, head, tail;
    unsigned magic, compat_features, incompat_features, header_length;
    struct io_event io_events[];
};

/* Every rejection must contain the literal "FAIL": the boot gate greps for
 * "aio_probe: FAIL" and would otherwise wait out its whole timeout. */
#define FAIL(...) do { printf("aio_probe: FAIL "); printf(__VA_ARGS__); return 1; } while (0)

int main(void) {
    const char *path = "/tmp/aio_probe.dat";
    const char payload[] = "AIODATA0";       /* 8 bytes, no NUL read-back */
    int wfd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (wfd < 0) FAIL("open-w\n");
    if (write(wfd, payload, 8) != 8) FAIL("write\n");
    close(wfd);

    int fd = open(path, O_RDONLY);
    if (fd < 0) FAIL("open-r\n");

    unsigned long ctx = 0;                    /* MUST be zero on entry */
    long rc = syscall(NR_IO_SETUP, 8u, &ctx);
    if (rc != 0) FAIL("io_setup FAIL rc=%ld\n", rc);

    /* The context IS the ring mapping. */
    struct aio_ring *ring = (struct aio_ring *)ctx;
    if (ring->magic != AIO_RING_MAGIC) FAIL("ring magic=%#x\n", ring->magic);
    if (ring->header_length != sizeof(struct aio_ring)) FAIL("ring hdrlen=%u\n", ring->header_length);
    if (ring->compat_features != 1u) FAIL("ring compat=%u\n", ring->compat_features);
    if (ring->incompat_features != 0u) FAIL("ring incompat=%u\n", ring->incompat_features);
    /* The slot count is rounded up to fill whole pages, so it is larger than
     * the 8 events asked for. */
    if (ring->nr <= 8u) FAIL("ring nr=%u\n", ring->nr);
    if (ring->head != 0u || ring->tail != 0u) FAIL("ring not empty h=%u t=%u\n", ring->head, ring->tail);

    /* *ctxp must be zero on entry. */
    unsigned long dup = ctx;
    if (syscall(NR_IO_SETUP, 8u, &dup) != -1 || errno != EINVAL) FAIL("nonzero ctxp not EINVAL\n");

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
    cb.aio_key        = 0xdeadbeefu;          /* the kernel overwrites this */

    struct iocb *cbp = &cb;
    rc = syscall(NR_IO_SUBMIT, ctx, (long)1, &cbp);
    if (rc != 1) FAIL("io_submit FAIL rc=%ld\n", rc);
    if (cb.aio_key != 0u) FAIL("aio_key not stamped: %#x\n", cb.aio_key);

    /* The completion is visible in the shared ring before any reap syscall. */
    if (ring->tail != 1u) FAIL("ring tail=%u after submit\n", ring->tail);
    if (ring->io_events[0].data != 0xABCDu) FAIL("ring ev.data=%llx\n",
        (unsigned long long)ring->io_events[0].data);
    if (ring->io_events[0].res != 8) FAIL("ring ev.res=%lld\n",
        (long long)ring->io_events[0].res);

    struct io_event ev;
    memset(&ev, 0, sizeof ev);
    rc = syscall(NR_IO_GETEVENTS, ctx, (long)1, (long)1, &ev, (void *)0);
    if (rc != 1) FAIL("io_getevents FAIL rc=%ld\n", rc);
    if (ring->head != 1u) FAIL("ring head=%u after reap\n", ring->head);

    if (ev.data != 0xABCDu) FAIL("bad data=%llx\n", (unsigned long long)ev.data);
    if (ev.obj != (uint64_t)(uintptr_t)&cb) FAIL("bad obj\n");
    if (ev.res != 8) FAIL("bad res=%lld\n", (long long)ev.res);
    if (memcmp(buf, payload, 8) != 0) FAIL("content mismatch\n");

    /* A zero timeout on an empty ring returns 0, not a block. */
    struct { long sec, nsec; } zero_ts = { 0, 0 };
    rc = syscall(NR_IO_GETEVENTS, ctx, (long)1, (long)1, &ev, &zero_ts);
    if (rc != 0) FAIL("empty getevents rc=%ld\n", rc);

    /* min_nr > nr is EINVAL. */
    if (syscall(NR_IO_GETEVENTS, ctx, (long)2, (long)1, &ev, &zero_ts) != -1 || errno != EINVAL)
        FAIL("min_nr>nr not EINVAL\n");

    /* An already-complete iocb cannot be cancelled. */
    if (syscall(NR_IO_CANCEL, ctx, &cb, &ev) != -1 || errno != EINVAL)
        FAIL("cancel of complete iocb not EINVAL\n");

    /* Forwards-compatibility gate: a set reserved field is EINVAL. */
    struct iocb bad = cb;
    bad.aio_reserved2 = 1;
    struct iocb *badp = &bad;
    if (syscall(NR_IO_SUBMIT, ctx, (long)1, &badp) != -1 || errno != EINVAL)
        FAIL("reserved field not EINVAL\n");

    /* IOCB_CMD_NOOP is enumerated but not accepted. */
    bad = cb;
    bad.aio_lio_opcode = IOCB_CMD_NOOP;
    if (syscall(NR_IO_SUBMIT, ctx, (long)1, &badp) != -1 || errno != EINVAL)
        FAIL("NOOP not EINVAL\n");

    /* An outstanding poll request is cancellable and reports EINPROGRESS. */
    int pfd[2];
    if (pipe(pfd) != 0) FAIL("pipe\n");
    struct iocb pl;
    memset(&pl, 0, sizeof pl);
    pl.aio_data       = 0x5150u;
    pl.aio_lio_opcode = IOCB_CMD_POLL;
    pl.aio_fildes     = (uint32_t)pfd[0];
    pl.aio_buf        = POLLIN;               /* nothing written yet */
    struct iocb *plp = &pl;
    rc = syscall(NR_IO_SUBMIT, ctx, (long)1, &plp);
    if (rc != 1) FAIL("poll submit FAIL rc=%ld\n", rc);
    if (syscall(NR_IO_CANCEL, ctx, &pl, &ev) != -1 || errno != EINPROGRESS)
        FAIL("poll cancel not EINPROGRESS (errno=%d)\n", errno);

    /* A poll request whose condition already holds completes at submit. */
    if (write(pfd[1], "x", 1) != 1) FAIL("pipe write\n");
    memset(&pl, 0, sizeof pl);
    pl.aio_data       = 0x5151u;
    pl.aio_lio_opcode = IOCB_CMD_POLL;
    pl.aio_fildes     = (uint32_t)pfd[0];
    pl.aio_buf        = POLLIN;
    rc = syscall(NR_IO_SUBMIT, ctx, (long)1, &plp);
    if (rc != 1) FAIL("ready poll submit FAIL rc=%ld\n", rc);
    memset(&ev, 0, sizeof ev);
    rc = syscall(NR_IO_GETEVENTS, ctx, (long)1, (long)1, &ev, &zero_ts);
    if (rc != 1) FAIL("ready poll reap rc=%ld\n", rc);
    if (ev.data != 0x5151u) FAIL("ready poll data=%llx\n", (unsigned long long)ev.data);
    if ((ev.res & POLLIN) == 0) FAIL("ready poll res=%lld\n", (long long)ev.res);

    if (syscall(NR_IO_DESTROY, ctx) != 0) FAIL("io_destroy\n");
    /* The context is gone: a second destroy is EINVAL. */
    if (syscall(NR_IO_DESTROY, ctx) != -1 || errno != EINVAL) FAIL("double destroy not EINVAL\n");

    printf("aio_probe: PASS\n");
    return 0;
}
