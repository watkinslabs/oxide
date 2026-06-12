/* /bin/io_uring_reg_probe — io_uring_register(2) real-semantics smoke.
 *
 * Proves io_uring_register actually registers resources (it used to be a
 * silent return-0 no-op, linux2.md §2.7). Exercises:
 *   1. IORING_REGISTER_BUFFERS  → 0
 *   2. re-REGISTER_BUFFERS       → -EBUSY (must unregister first)
 *   3. IORING_OP_READ_FIXED      reading a pipe into the registered buffer:
 *      CQE res > 0 and the bytes land in the registered buffer
 *   4. IORING_REGISTER_PROBE     → IORING_OP_READ marked SUPPORTED
 *   5. IORING_UNREGISTER_BUFFERS → 0
 *
 * Raw syscalls only (no liburing). Reuses io_uring_probe's single-page ring
 * layout: SQ hdr 0x000, SQ ring 0x010, CQ hdr 0x100, CQ ring 0x110, SQE
 * array 0x800. io_uring_setup=425 / enter=426 / register=427 are arch-common.
 *
 * SIGALRM watchdog (3s) guarantees the probe can never hang the boot. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#define OFF_SQ_RING 0x010
#define OFF_CQ_HDR  0x100
#define OFF_CQ_RING 0x110
#define OFF_SQE_ARR 0x800

#define IORING_OP_READ_FIXED 4
#define IORING_OP_READ       22

#define IORING_REGISTER_BUFFERS    0
#define IORING_UNREGISTER_BUFFERS  1
#define IORING_REGISTER_PROBE      8
#define IO_URING_OP_SUPPORTED      (1u << 0)

struct iovec_u { void *base; size_t len; };

static void fail(const char *why) { printf("io_uring_reg_probe: FAIL %s\n", why); _exit(1); }
static void on_alrm(int s) { (void)s; fail("watchdog timeout"); }

static long io_setup(unsigned e, void *params) { return syscall(425, e, params); }
static long io_enter(int fd, unsigned ts, unsigned mc) { return syscall(426, fd, ts, mc, 0u, 0, 0); }
static long io_reg(int fd, unsigned op, void *arg, unsigned nr) { return syscall(427, fd, op, arg, nr); }

int main(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alrm; sigaction(SIGALRM, &sa, 0);
    alarm(3);

    unsigned char params[120];
    memset(params, 0, sizeof params);
    long fd = io_setup(4, params);
    if (fd < 0) fail("setup");

    uint8_t *base = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, (int)fd, 0);
    if (base == MAP_FAILED) fail("mmap");

    /* A 64-byte registered buffer. */
    static uint8_t buf[64];
    memset(buf, 0, sizeof buf);
    struct iovec_u iov = { buf, sizeof buf };

    /* 1. register the buffer. */
    if (io_reg((int)fd, IORING_REGISTER_BUFFERS, &iov, 1) != 0) fail("register_buffers");

    /* 2. re-register without unregister → EBUSY. */
    long r = io_reg((int)fd, IORING_REGISTER_BUFFERS, &iov, 1);
    if (r != -1 || errno != EBUSY) {
        char m[64]; snprintf(m, sizeof m, "ebusy r=%ld e=%d", r, errno); fail(m);
    }

    /* 3. READ_FIXED from a pipe into the registered buffer. */
    int p[2];
    if (pipe(p) < 0) fail("pipe");
    const char msg[] = "io_uring_fixed_buf_works";
    if (write(p[1], msg, sizeof msg) != (ssize_t)sizeof msg) fail("pipe_write");

    uint32_t entries = *(volatile uint32_t *)(base + 0x00C);
    uint32_t mask = entries ? entries - 1 : 3;
    volatile uint32_t *sq_head = (volatile uint32_t *)(base + 0x000);
    volatile uint32_t *sq_tail = (volatile uint32_t *)(base + 0x004);
    volatile uint32_t *sq_arr  = (volatile uint32_t *)(base + OFF_SQ_RING);
    volatile uint32_t *cq_tail = (volatile uint32_t *)(base + OFF_CQ_HDR + 4);

    /* SQE: opcode@0, flags@1, fd@4, off@8, addr@16, len@24, user_data@32,
     * buf_index@40. READ_FIXED ignores addr; uses buf_index + off/len. */
    uint8_t *sqe = base + OFF_SQE_ARR + 0 * 64;
    memset(sqe, 0, 64);
    sqe[0] = IORING_OP_READ_FIXED;
    *(int32_t  *)(sqe + 4)  = p[0];          /* read end of the pipe */
    *(uint64_t *)(sqe + 8)  = 0;             /* off within the buffer */
    *(uint32_t *)(sqe + 24) = sizeof msg;    /* len */
    *(uint64_t *)(sqe + 32) = 0xF1Eull;      /* user_data */
    *(uint16_t *)(sqe + 40) = 0;             /* buf_index 0 */

    uint32_t head = *sq_head;
    sq_arr[head & mask] = 0;
    *sq_tail = head + 1;

    long n = io_enter((int)fd, 1u, 1u);
    if (n < 1) fail("enter");
    if (*cq_tail < 1) fail("no_cqe");

    uint8_t *cqe = base + OFF_CQ_RING + 0 * 16;
    uint64_t ud = *(uint64_t *)(cqe + 0);
    int32_t  res = *(int32_t *)(cqe + 8);
    if (ud != 0xF1Eull) fail("cqe_user_data");
    if (res <= 0) { char m[48]; snprintf(m, sizeof m, "read_fixed res=%d", res); fail(m); }
    if (memcmp(buf, msg, sizeof msg) != 0) fail("buf_data");

    /* 4. probe: IORING_OP_READ must be reported SUPPORTED. */
    unsigned char probe[16 + 64 * 8];
    memset(probe, 0, sizeof probe);
    if (io_reg((int)fd, IORING_REGISTER_PROBE, probe, 64) != 0) fail("register_probe");
    uint8_t ops_len = probe[1];
    if (ops_len < IORING_OP_READ + 1) fail("probe_ops_len");
    uint8_t *op = probe + 16 + IORING_OP_READ * 8;
    uint16_t flags = *(uint16_t *)(op + 2);
    if ((flags & IO_URING_OP_SUPPORTED) == 0) fail("read_not_supported");

    /* 5. unregister the buffers. */
    if (io_reg((int)fd, IORING_UNREGISTER_BUFFERS, 0, 0) != 0) fail("unregister_buffers");

    printf("io_uring_reg_probe: PASS\n");
    return 0;
}
