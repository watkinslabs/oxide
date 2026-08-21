#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/ioctl.h>
#include <unistd.h>

enum {
    PAGE_BYTES = 4096,
    VERSION_OFFSET = 1024,
    LAST_PAGE_OFFSET = 1028,
    BAD_PAGE_COUNT_OFFSET = 1032,
    NONCE_BYTES = 32,
};

#define BLKGETSIZE64 _IOR(0x12, 114, uint64_t)
#define FRESH_GUARD "/var/lib/oxide-hibernate-pending"

static void fail(const char *operation) {
    fprintf(stderr, "HIBERNATE-PROBE-FAIL:%s:%s\n", operation, strerror(errno));
    fflush(stderr);
    exit(1);
}

static void put_u32(unsigned char *page, size_t offset, uint32_t value) {
    page[offset] = (unsigned char)value;
    page[offset + 1] = (unsigned char)(value >> 8);
    page[offset + 2] = (unsigned char)(value >> 16);
    page[offset + 3] = (unsigned char)(value >> 24);
}

static void initialize_swap(const char *path) {
    unsigned char page[PAGE_BYTES] = {0};
    struct stat status;
    uint64_t bytes = 0;
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) fail("open-swap");
    if (fstat(fd, &status) < 0) fail("stat-swap");
    if (ioctl(fd, BLKGETSIZE64, &bytes) < 0) {
        if (!S_ISREG(status.st_mode) || status.st_size <= 0) fail("size-swap");
        bytes = (uint64_t)status.st_size;
    }
    uint64_t pages = bytes / PAGE_BYTES;
    if (pages < 3 || pages - 1 > UINT32_MAX) {
        errno = EOVERFLOW;
        fail("swap-size");
    }
    put_u32(page, VERSION_OFFSET, 1);
    put_u32(page, LAST_PAGE_OFFSET, (uint32_t)(pages - 1));
    put_u32(page, BAD_PAGE_COUNT_OFFSET, 0);
    memcpy(page + PAGE_BYTES - 10, "SWAPSPACE2", 10);
    if (pwrite(fd, page, sizeof(page), 0) != (ssize_t)sizeof(page)) fail("write-swap-header");
    if (fsync(fd) < 0) fail("sync-swap-header");
    if (close(fd) < 0) fail("close-swap");
}

static void arm_fresh_guard(void) {
    int fd = open(FRESH_GUARD, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) fail("create-fresh-guard");
    static const char marker[] = "pending\n";
    if (write(fd, marker, sizeof(marker) - 1) != (ssize_t)(sizeof(marker) - 1)) fail("write-fresh-guard");
    if (fsync(fd) < 0) fail("sync-fresh-guard");
    if (close(fd) < 0) fail("close-fresh-guard");
    fd = open("/var/lib", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0 || fsync(fd) < 0 || close(fd) < 0) fail("sync-fresh-guard-directory");
}

static int check_fresh_guard(void) {
    if (access(FRESH_GUARD, F_OK) < 0) return errno == ENOENT ? 0 : 1;
    fputs("HIBERNATE-FRESH-BOOT-FAIL\n", stdout);
    fflush(stdout);
    return 0;
}

static void write_sysfs(const char *path, const char *value) {
    size_t length = strlen(value);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) fail(path);
    if (write(fd, value, length) != (ssize_t)length) fail(path);
    if (close(fd) < 0) fail(path);
}

int main(int argc, char **argv) {
    unsigned char nonce[NONCE_BYTES];
    if (argc == 2 && strcmp(argv[1], "--fresh-guard") == 0) return check_fresh_guard();
    if (argc == 3 && strcmp(argv[1], "--header-only") == 0) {
        initialize_swap(argv[2]);
        return 0;
    }
    if (argc != 2) {
        fprintf(stderr, "usage: %s /dev/swap-device\n", argv[0]);
        return 2;
    }
    initialize_swap(argv[1]);
    if (swapon(argv[1], 0) < 0) fail("swapon");
    write_sysfs("/sys/power/resume", argv[1]);
    write_sysfs("/sys/power/disk", "shutdown\n");
    arm_fresh_guard();
    if (getrandom(nonce, sizeof(nonce), 0) != (ssize_t)sizeof(nonce)) fail("getrandom");
    fputs("HIBERNATE-REQUEST\n", stdout);
    fflush(stdout);
    write_sysfs("/sys/power/state", "disk\n");

    fputs("HIBERNATE-NONCE:", stdout);
    for (size_t index = 0; index < sizeof(nonce); ++index) printf("%02x", nonce[index]);
    fputc('\n', stdout);
    if (unlink(FRESH_GUARD) < 0) fail("clear-fresh-guard");
    int guard_dir = open("/var/lib", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (guard_dir < 0 || fsync(guard_dir) < 0 || close(guard_dir) < 0) fail("sync-cleared-fresh-guard");
    fputs("HIBERNATE-RESUME-PASS\n", stdout);
    fflush(stdout);
    return 0;
}
