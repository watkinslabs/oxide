// /bin/mmap_zero_smoke — verifies the MAP_ANONYMOUS zero-fill
// contract for big allocations (B46).
//
// dhcpcd hit a #GP in free_options walking ifo->environ at offset
// 0x10120 inside a calloc(1, sizeof(struct if_options)) buffer.
// The value read at that offset was non-canonical garbage, not
// zero — which is what calloc + MAP_ANONYMOUS together guarantee.
// This probe replicates the access pattern (mmap 128 KiB anon,
// read a u64 from offset 0x10120, expect zero), forks a child to
// repeat the same after a COW boundary, and verifies the same
// guarantee survives fork.

#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <string.h>

#define PASS_MSG "mmap_zero_smoke: PASS\n"
#define FAIL_MSG "mmap_zero_smoke: FAIL\n"

#define LEN (128 * 1024)   /* > 64 KiB so musl uses mmap, not brk */
#define OFF 0x10120        /* the exact dhcpcd free_options offset */

static int probe(void) {
    unsigned char *p = mmap(NULL, LEN, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 2;
    // First touch is the read — must zero-fill on demand.
    unsigned long v;
    memcpy(&v, p + OFF, sizeof(v));
    if (v != 0) return 3;
    // Repeat across multiple page boundaries (every 4 KiB up to
    // 16 KiB past OFF) so a one-page-zero-then-stale-pages bug
    // surfaces.
    for (unsigned long i = 0; i < (LEN - OFF); i += 0x1000) {
        memcpy(&v, p + OFF + i, sizeof(v));
        if (v != 0) return 4;
    }
    munmap(p, LEN);
    return 0;
}

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    // Parent probe.
    if (probe() != 0) { write(1, FAIL_MSG, sizeof(FAIL_MSG) - 1); return 1; }
    // Child probe (post-fork COW path).
    pid_t pid = fork();
    if (pid < 0) { write(1, FAIL_MSG, sizeof(FAIL_MSG) - 1); return 1; }
    if (pid == 0) { _exit(probe()); }
    int status = 0;
    waitpid(pid, &status, 0);
    if ((status & 0x7f) != 0 || ((status >> 8) & 0xff) != 0) {
        write(1, FAIL_MSG, sizeof(FAIL_MSG) - 1);
        return 1;
    }
    write(1, PASS_MSG, sizeof(PASS_MSG) - 1);
    return 0;
}
