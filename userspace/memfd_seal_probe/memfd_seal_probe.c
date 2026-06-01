// /bin/memfd_seal_probe — memfd file sealing (K5). systemd passes sealed
// memfds over IPC; a peer adds F_SEAL_WRITE so the content can't change.
// Verifies: a sealable memfd accepts F_ADD_SEALS(F_SEAL_WRITE), reports it
// via F_GET_SEALS, then rejects further writes (EPERM); a non-sealable
// memfd returns EINVAL on F_ADD_SEALS.

#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/syscall.h>

#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif
#define MFD_ALLOW_SEALING 0x0002
#define F_ADD_SEALS  1033
#define F_GET_SEALS  1034
#define F_SEAL_WRITE 0x0008

static int memfd(const char *n, unsigned f) {
    return (int)syscall(__NR_memfd_create, n, f);
}

int main(void) {
    int fails = 0;

    // Sealable memfd: write, seal WRITE, verify, then write must fail.
    int fd = memfd("seal", MFD_ALLOW_SEALING);
    if (fd < 0) { printf("memfd_seal_probe: FAIL memfd errno=%d\n", errno); return 1; }
    if (write(fd, "abcd", 4) != 4) { printf("memfd_seal_probe: FAIL pre-write errno=%d\n", errno); return 1; }
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) != 0) {
        printf("memfd_seal_probe: FAIL add-seal errno=%d\n", errno); fails++;
    }
    int got = fcntl(fd, F_GET_SEALS, 0);
    if (!(got & F_SEAL_WRITE)) { printf("memfd_seal_probe: FAIL get-seals=%d\n", got); fails++; }
    lseek(fd, 0, SEEK_SET);
    if (write(fd, "x", 1) >= 0 || errno != EPERM) {
        printf("memfd_seal_probe: FAIL post-seal write not EPERM (errno=%d)\n", errno); fails++;
    }
    close(fd);

    // Non-sealable memfd: F_ADD_SEALS → EINVAL.
    int fd2 = memfd("nosel", 0);
    if (fd2 < 0) { printf("memfd_seal_probe: FAIL memfd2 errno=%d\n", errno); return 1; }
    if (fcntl(fd2, F_ADD_SEALS, F_SEAL_WRITE) == 0 || errno != EINVAL) {
        printf("memfd_seal_probe: FAIL non-sealable not EINVAL (errno=%d)\n", errno); fails++;
    }
    close(fd2);

    if (fails == 0) { printf("memfd_seal_probe: PASS memfd F_ADD_SEALS/F_SEAL_WRITE\n"); return 0; }
    return 1;
}
