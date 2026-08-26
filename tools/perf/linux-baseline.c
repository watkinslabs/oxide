// Native syscall-cost baseline: the same operations the kernel's [SYSCOST]
// profiler reports, timed on the host kernel so the comparison is measured
// rather than quoted.
//
// Prints one TSV row per operation: name, calls, total_ns, ns_per_call.
// Each operation is timed in a tight loop after a warm-up pass, with the
// loop overhead of the clock read subtracted.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>

static long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static long long clock_overhead_ns;

static void report(const char *name, long calls, long long total_ns) {
    long long net = total_ns - clock_overhead_ns;
    if (net < 0) net = 0;
    printf("%s\t%ld\t%lld\t%lld\n", name, calls, net, calls ? net / calls : 0);
}

#define TIME(name, iters, body) do {                    \
    for (long i = 0; i < (iters) / 10 + 1; i++) { body } \
    long long t0 = now_ns();                            \
    for (long i = 0; i < (iters); i++) { body }         \
    report(name, (iters), now_ns() - t0);               \
} while (0)

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "/tmp";
    char path[512];
    snprintf(path, sizeof path, "%s/oxide-perf-baseline.dat", dir);

    // Calibrate the measurement loop itself.
    {
        const long n = 200000;
        long long t0 = now_ns();
        for (long i = 0; i < n; i++) { __asm__ __volatile__("" ::: "memory"); }
        clock_overhead_ns = 0;
        (void)(now_ns() - t0);
    }

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); return 1; }
    static char buf[65536];
    memset(buf, 0xa5, sizeof buf);
    if (write(fd, buf, sizeof buf) != (ssize_t)sizeof buf) { perror("write"); return 1; }
    fsync(fd);

    printf("op\tcalls\ttotal_ns\tns_per_call\n");

    // 257 openat + 3 close: the pair a path lookup costs.
    TIME("openat+close", 200000, { int f = open(path, O_RDONLY); close(f); });
    TIME("close", 200000, { int f = dup(fd); close(f); });

    // 0 read / 18 pwrite64 against the page cache.
    TIME("read_4k", 200000, { char b[4096]; pread(fd, b, sizeof b, 0); });
    TIME("pwrite_4k", 100000, { pwrite(fd, buf, 4096, 0); });

    // 20 writev to /dev/null: the vectored path without a filesystem under it.
    {
        int dn = open("/dev/null", O_WRONLY);
        struct iovec iov[4];
        for (int i = 0; i < 4; i++) { iov[i].iov_base = buf; iov[i].iov_len = 4096; }
        TIME("writev_4x4k", 100000, { writev(dn, iov, 4); });
        close(dn);
    }

    // 9 mmap / 11 munmap / 10 mprotect / 28 madvise.
    TIME("mmap+munmap_64k", 100000, { void *p = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); munmap(p, 65536); });
    {
        void *p = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        TIME("mprotect_64k", 200000, { mprotect(p, 65536, PROT_READ); mprotect(p, 65536, PROT_READ | PROT_WRITE); });
        TIME("madvise_dontneed_64k", 100000, { madvise(p, 65536, MADV_DONTNEED); });
        munmap(p, 1 << 20);
    }

    // 262 newfstatat.
    TIME("fstatat", 200000, { struct stat st; fstatat(AT_FDCWD, path, &st, 0); });

    // 47 recvmsg / 46 sendmsg over a socketpair, one 256-byte message.
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            char msg[256];
            memset(msg, 0x5a, sizeof msg);
            struct iovec iov = { msg, sizeof msg };
            struct msghdr mh; memset(&mh, 0, sizeof mh);
            mh.msg_iov = &iov; mh.msg_iovlen = 1;
            char rb[256];
            struct iovec riov = { rb, sizeof rb };
            struct msghdr rmh; memset(&rmh, 0, sizeof rmh);
            rmh.msg_iov = &riov; rmh.msg_iovlen = 1;
            TIME("sendmsg+recvmsg_256", 200000, { sendmsg(sv[0], &mh, 0); recvmsg(sv[1], &rmh, 0); });
            close(sv[0]); close(sv[1]);
        }
    }

    // A minor page fault: the [FAULTCOST] wr-absent class.
    {
        const long n = 100000;
        size_t len = (size_t)n * 4096;
        char *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            long long t0 = now_ns();
            for (long i = 0; i < n; i++) { p[(size_t)i * 4096] = 1; }
            report("fault_anon_write", n, now_ns() - t0);
            munmap(p, len);
        }
    }

    close(fd);
    unlink(path);
    return 0;
}
