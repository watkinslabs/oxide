// /bin/uffd_probe — F1 end-to-end guard: userfaultfd(2) MISSING-mode must
// deliver a real page-fault event and let a monitor thread install the page.
//
// Flow (Linux uffd MISSING pattern): create a uffd, UFFDIO_API, mmap an anon
// page, UFFDIO_REGISTER(MODE_MISSING) it. A monitor thread blocks in read(uffd);
// the main thread's first read of the region faults → the kernel enqueues a
// PAGEFAULT uffd_msg, wakes the monitor, and BLOCKS the faulting thread. The
// monitor UFFDIO_COPYs a page of 'A' at the faulting address, which maps a real
// frame into the (shared) mm and wakes the faulter; the faulting load then sees
// 'A'. Monitor + faulter share one mm (pthread = CLONE_VM), the case the kernel
// COPY path targets. Pre-F1 the fault was silently zero-filled and read() on the
// uffd returned 0 forever → this hangs / reads 0, never 'A'.
//
// The uapi is defined inline: the x86 cross-musl sysroot does not ship
// <linux/userfaultfd.h>. Struct field ORDER matches the kernel ABI:
// uffd_msg = event@0, flags@8, address@16, ptid@24.

#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>

#define PASS "uffd_probe: PASS\n"
#define FAIL "uffd_probe: FAIL\n"

#define UFFD_API                    0xAAULL
#define UFFD_EVENT_PAGEFAULT        0x12
#define UFFDIO_REGISTER_MODE_MISSING 1ULL

#define UFFDIO_API      0xc018aa3fULL
#define UFFDIO_REGISTER 0xc020aa00ULL
#define UFFDIO_COPY     0xc028aa03ULL

struct up_api      { uint64_t api, features; };
struct up_range    { uint64_t start, len; };
struct up_register { struct up_range range; uint64_t mode, ioctls; };
struct up_copy     { uint64_t dst, src, len, mode, copy; };
struct up_msg        { uint8_t event; uint8_t r0; uint16_t r1; uint32_t r2;
                         uint64_t flags; uint64_t address; uint64_t ptid; };

static int   uffd;
static char *region;
static long  page;

// Monitor: wait for the fault event, install a page of 'A' at the faulting addr.
static void *monitor(void *arg) {
    (void)arg;
    struct up_msg msg;
    for (;;) {
        ssize_t n = read(uffd, &msg, sizeof msg);
        if (n <= 0) continue;
        if (msg.event != UFFD_EVENT_PAGEFAULT) continue;
        static char src[4096];
        memset(src, 'A', sizeof src);
        struct up_copy c;
        memset(&c, 0, sizeof c);
        c.dst = msg.address & ~(uint64_t)(page - 1);
        c.src = (uintptr_t)src;
        c.len = page;
        ioctl(uffd, UFFDIO_COPY, &c);
        return 0;
    }
}

int main(void) {
    page = sysconf(_SC_PAGESIZE);

    uffd = syscall(SYS_userfaultfd, O_CLOEXEC);
    if (uffd < 0) { write(1, FAIL, sizeof FAIL - 1); return 1; }

    struct up_api api;
    memset(&api, 0, sizeof api);
    api.api = UFFD_API;
    if (ioctl(uffd, UFFDIO_API, &api) < 0) { write(1, FAIL, sizeof FAIL - 1); return 1; }

    region = mmap(0, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { write(1, FAIL, sizeof FAIL - 1); return 1; }

    struct up_register reg;
    memset(&reg, 0, sizeof reg);
    reg.range.start = (uintptr_t)region;
    reg.range.len   = page;
    reg.mode        = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &reg) < 0) { write(1, FAIL, sizeof FAIL - 1); return 1; }

    pthread_t th;
    if (pthread_create(&th, 0, monitor, 0) != 0) { write(1, FAIL, sizeof FAIL - 1); return 1; }

    // First touch faults → blocks → monitor COPYs → resumes with 'A'.
    char got = region[0];
    pthread_join(th, 0);

    if (got == 'A') { write(1, PASS, sizeof PASS - 1); return 0; }
    write(1, FAIL, sizeof FAIL - 1);
    return 1;
}
