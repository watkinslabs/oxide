// /bin/pmadvise_probe — exercises process_madvise(2) (nr 440) and
// process_mrelease(2) (nr 448) via raw syscalls against a self pidfd.
//
// process_madvise: MADV_DONTNEED over an anon range drops the pages; the
// range must refault as zero. Assert the returned byte count == range len
// and the first byte reads back 0 after the dirty write.
//
// process_mrelease: releasing a LIVE (non-exiting) self target must fail
// EINVAL — Linux forbids self-release and requires the target be exiting.
//
// Expected on a working kernel:
//   pmadvise_probe: PASS
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_process_madvise
#define SYS_process_madvise 440
#endif
#ifndef SYS_process_mrelease
#define SYS_process_mrelease 448
#endif

#define MADV_DONTNEED 4
#define RANGE_LEN     65536u

struct iov { void *base; unsigned long len; };

int main(void) {
    long pfd = syscall(SYS_pidfd_open, getpid(), 0);
    if (pfd < 0) { printf("pmadvise_probe: FAIL pidfd_open errno=%d\n", errno); return 1; }

    unsigned char *p = mmap(NULL, RANGE_LEN, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { printf("pmadvise_probe: FAIL mmap errno=%d\n", errno); return 1; }
    memset(p, 0xAB, RANGE_LEN);
    if (p[0] != 0xAB) { printf("pmadvise_probe: FAIL predirty\n"); return 1; }

    struct iov iov = { p, RANGE_LEN };
    long r = syscall(SYS_process_madvise, (int)pfd, &iov, 1UL, (unsigned long)MADV_DONTNEED, 0UL);
    if (r != (long)RANGE_LEN) {
        printf("pmadvise_probe: FAIL process_madvise r=%ld errno=%d\n", r, errno);
        return 1;
    }
    // Page dropped -> refaults as zero.
    if (p[0] != 0x00) {
        printf("pmadvise_probe: FAIL refault nonzero=0x%02x\n", p[0]);
        return 1;
    }

    // process_mrelease on a live, non-exiting self target -> EINVAL.
    long r2 = syscall(SYS_process_mrelease, (int)pfd, 0UL);
    if (!(r2 == -1 && errno == EINVAL)) {
        printf("pmadvise_probe: FAIL mrelease r2=%ld errno=%d (want -1/EINVAL)\n", r2, errno);
        return 1;
    }

    printf("pmadvise_probe: PASS\n");
    return 0;
}
