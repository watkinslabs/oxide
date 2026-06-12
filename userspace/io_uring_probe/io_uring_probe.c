/* /bin/io_uring_probe — end-to-end io_uring round-trip smoke.
 *
 * Proves userspace can actually USE io_uring: io_uring_setup(2) returns an
 * fd, mmap(fd) maps the shared ring page, we submit one IORING_OP_NOP SQE,
 * io_uring_enter(2) drives the kernel to consume it and post a CQE, and we
 * read the completion back. Before the ring page was mmap-able this was
 * impossible (the rings lived in kernel-only HHDM memory).
 *
 * Layout note: oxide lays the SQ ring, CQ ring and SQE array out in ONE
 * page at fixed offsets (SQ hdr 0x000, SQ ring 0x010, CQ hdr 0x100, CQ ring
 * 0x110, SQE array 0x800) — so a single mmap(offset=0) exposes all three.
 * (liburing's 3-region mmap layout is a separate follow-up.)
 *
 * io_uring_setup=425 / io_uring_enter=426 are arch-common (same on x86_64
 * and aarch64). */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>

#define PASS "io_uring_probe: PASS\n"

/* struct io_uring_params is 120 bytes; we only read the few fields we need. */
#define OFF_SQ_RING 0x010
#define OFF_CQ_HDR  0x100
#define OFF_CQ_RING 0x110
#define OFF_SQE_ARR 0x800
#define IORING_OP_NOP 0

int main(void) {
    unsigned char params[120];
    memset(params, 0, sizeof params);
    long fd = syscall(425 /*io_uring_setup*/, 4 /*entries*/, params);
    if (fd < 0) { printf("io_uring_probe: setup FAIL rv=%ld\n", fd); return 1; }

    uint8_t *base = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, (int)fd, 0);
    if (base == MAP_FAILED) { printf("io_uring_probe: mmap FAIL\n"); return 1; }

    /* SQ head/tail at 0x000/0x004; ring_entries at 0x00C; mask = entries-1. */
    volatile uint32_t *sq_head = (volatile uint32_t *)(base + 0x000);
    volatile uint32_t *sq_tail = (volatile uint32_t *)(base + 0x004);
    uint32_t entries = *(volatile uint32_t *)(base + 0x00C);
    uint32_t mask = entries ? entries - 1 : 3;
    volatile uint32_t *sq_arr = (volatile uint32_t *)(base + OFF_SQ_RING);
    volatile uint32_t *cq_tail = (volatile uint32_t *)(base + OFF_CQ_HDR + 4);

    /* Build SQE[0] = NOP, user_data = 0xCAFE. SQE is 64 bytes:
     * opcode@0, fd@4, off@8, addr@16, len@24, user_data@32. */
    uint8_t *sqe = base + OFF_SQE_ARR + 0 * 64;
    memset(sqe, 0, 64);
    sqe[0] = IORING_OP_NOP;
    *(uint64_t *)(sqe + 32) = 0xCAFEu;

    uint32_t head = *sq_head;
    sq_arr[head & mask] = 0;          /* this slot points at SQE index 0 */
    *sq_tail = head + 1;              /* publish one SQE */

    long n = syscall(426 /*io_uring_enter*/, (int)fd, 1u, 1u, 0u, 0, 0);
    if (n < 1) { printf("io_uring_probe: enter FAIL rv=%ld\n", n); return 1; }

    if (*cq_tail < 1) { printf("io_uring_probe: no CQE (cq_tail=%u)\n", *cq_tail); return 1; }
    /* CQE[0] at CQ ring: user_data@0 (u64), res@8 (i32). */
    uint8_t *cqe = base + OFF_CQ_RING + 0 * 16;
    uint64_t ud = *(uint64_t *)(cqe + 0);
    int32_t res = *(int32_t *)(cqe + 8);
    if (ud != 0xCAFEu || res != 0) {
        printf("io_uring_probe: bad CQE ud=%llx res=%d\n", (unsigned long long)ud, res);
        return 1;
    }
    printf(PASS);
    return 0;
}
