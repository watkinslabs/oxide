// /usr/local/bin/swapfile_probe — real ext4 swapfile lifecycle probe.
// Creates a fully initialized, page-aligned regular file on the root ext4,
// writes the Linux SWAPSPACE2 header, activates it with libc swapon(3),
// verifies the canonical /proc/swaps view, then swapoff(3)s and removes it.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/types.h>
#include <unistd.h>

static const char SWAP_MAGIC[] = "SWAPSPACE2";

enum {
    PAGE_BYTES = 4096,
    SWAP_PAGE_COUNT = 32,
    SWAP_FILE_BYTES = PAGE_BYTES * SWAP_PAGE_COUNT,
    SWAP_HEADER_VERSION_OFFSET = 1024,
    SWAP_HEADER_LAST_PAGE_OFFSET = SWAP_HEADER_VERSION_OFFSET + sizeof(uint32_t),
    SWAP_HEADER_BAD_PAGE_COUNT_OFFSET = SWAP_HEADER_LAST_PAGE_OFFSET + sizeof(uint32_t),
    SWAP_MAGIC_BYTES = sizeof(SWAP_MAGIC) - 1,
    SWAP_HEADER_MAGIC_OFFSET = PAGE_BYTES - SWAP_MAGIC_BYTES,
    SWAPSPACE2_VERSION = 1,
    LAST_SWAP_PAGE = SWAP_PAGE_COUNT - 1,
    OWNER_READ_WRITE = S_IRUSR | S_IWUSR,
    NO_SWAP_BYTES = 0,
    SWAP_LIMIT_BYTES = PAGE_BYTES,
    TEXT_BUFFER_BYTES = 32,
};

static const char SWAP_FILE_PATH[] = "/var/tmp/oxide-swapfile-probe";
static const char PROC_SWAPS_PATH[] = "/proc/swaps";
static const char CGROUP_PATH[] = "/sys/fs/cgroup/swapfile_probe";
static const char CGROUP_SUBTREE_CONTROL[] = "/sys/fs/cgroup/cgroup.subtree_control";
static const char CGROUP_ROOT_PROCS[] = "/sys/fs/cgroup/cgroup.procs";
static const char CGROUP_ENABLE_MEMORY[] = "+memory";
static const char CGROUP_PROCS[] = "/cgroup.procs";
static const char CGROUP_SWAP_MAX[] = "/memory.swap.max";
static const char CGROUP_SWAP_CURRENT[] = "/memory.swap.current";
static const char PASS_LINE[] = "swapfile_probe: PASS ext4 swap plus memcg pageout accounting\n";

static void fail(const char *where) {
    printf("swapfile_probe: FAIL %s errno=%d\n", where, errno);
}

static int write_all_pages(int fd) {
    uint8_t page[PAGE_BYTES] = {0};
    for (uint32_t page_index = 0; page_index < SWAP_PAGE_COUNT; page_index++) {
        off_t offset = (off_t)page_index * PAGE_BYTES;
        if (pwrite(fd, page, sizeof(page), offset) != (ssize_t)sizeof(page)) return -1;
    }
    return 0;
}

static int write_swap_header(int fd) {
    uint8_t page[PAGE_BYTES] = {0};
    uint32_t version = SWAPSPACE2_VERSION;
    uint32_t last_page = LAST_SWAP_PAGE;
    uint32_t bad_page_count = 0;
    memcpy(page + SWAP_HEADER_VERSION_OFFSET, &version, sizeof(version));
    memcpy(page + SWAP_HEADER_LAST_PAGE_OFFSET, &last_page, sizeof(last_page));
    memcpy(page + SWAP_HEADER_BAD_PAGE_COUNT_OFFSET, &bad_page_count, sizeof(bad_page_count));
    memcpy(page + SWAP_HEADER_MAGIC_OFFSET, SWAP_MAGIC, SWAP_MAGIC_BYTES);
    if (pwrite(fd, page, sizeof(page), 0) != (ssize_t)sizeof(page)) return -1;
    return fsync(fd);
}

static int proc_reports_active_swapfile(void) {
    FILE *swaps = fopen(PROC_SWAPS_PATH, "re");
    if (swaps == NULL) return -1;
    char line[PAGE_BYTES];
    int found = 0;
    while (fgets(line, sizeof(line), swaps) != NULL) {
        if (strstr(line, SWAP_FILE_PATH) != NULL) { found = 1; break; }
    }
    if (fclose(swaps) != 0) return -1;
    return found;
}

static int write_text(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t length = strlen(text);
    int ok = write(fd, text, length) == (ssize_t)length;
    int saved = errno;
    close(fd);
    errno = saved;
    return ok ? 0 : -1;
}

static int read_number(const char *path, unsigned long long *value) {
    char text[TEXT_BUFFER_BYTES] = {0};
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t length = read(fd, text, sizeof(text) - 1);
    int saved = errno;
    close(fd);
    errno = saved;
    if (length <= 0) return -1;
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text) return -1;
    *value = parsed;
    return 0;
}

static int path_join(char *out, size_t capacity, const char *suffix) {
    int length = snprintf(out, capacity, "%s%s", CGROUP_PATH, suffix);
    return length > 0 && (size_t)length < capacity ? 0 : -1;
}

static int memcg_pageout_smoke(const char **failed_step) {
    char procs_path[sizeof(CGROUP_PATH) + sizeof(CGROUP_PROCS)] = {0};
    char swap_max_path[sizeof(CGROUP_PATH) + sizeof(CGROUP_SWAP_MAX)] = {0};
    char swap_current_path[sizeof(CGROUP_PATH) + sizeof(CGROUP_SWAP_CURRENT)] = {0};
    char pid_text[TEXT_BUFFER_BYTES] = {0};
    char deny_text[TEXT_BUFFER_BYTES] = {0};
    char limit_text[TEXT_BUFFER_BYTES] = {0};
    unsigned long long current = 0;
    unsigned char *page = MAP_FAILED;
    int attached = 0;
    int created = 0;
    int result = -1;
    const char *step = "enable-memory-controller";
    if (write_text(CGROUP_SUBTREE_CONTROL, CGROUP_ENABLE_MEMORY) != 0) goto out;
    step = "remove-stale-cgroup";
    rmdir(CGROUP_PATH);
    step = "create-cgroup";
    if (mkdir(CGROUP_PATH, OWNER_READ_WRITE | S_IXUSR) != 0) goto out;
    created = 1;
    step = "build-cgroup-paths";
    if (path_join(procs_path, sizeof(procs_path), CGROUP_PROCS) != 0
        || path_join(swap_max_path, sizeof(swap_max_path), CGROUP_SWAP_MAX) != 0
        || path_join(swap_current_path, sizeof(swap_current_path), CGROUP_SWAP_CURRENT) != 0) goto out;
    int pid_length = snprintf(pid_text, sizeof(pid_text), "%d", (int)getpid());
    int deny_length = snprintf(deny_text, sizeof(deny_text), "%u", NO_SWAP_BYTES);
    int limit_length = snprintf(limit_text, sizeof(limit_text), "%u", SWAP_LIMIT_BYTES);
    step = "format-cgroup-values";
    if (pid_length <= 0 || (size_t)pid_length >= sizeof(pid_text)
        || deny_length <= 0 || (size_t)deny_length >= sizeof(deny_text)
        || limit_length <= 0 || (size_t)limit_length >= sizeof(limit_text)) goto out;
    step = "set-swap-max-zero";
    if (write_text(swap_max_path, deny_text) != 0) goto out;
    step = "attach-probe-cgroup";
    if (write_text(procs_path, pid_text) != 0) goto out;
    attached = 1;
    page = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    step = "map-anonymous-page";
    if (page == MAP_FAILED) goto out;
    memset(page, UINT8_MAX, PAGE_BYTES);
    step = "pageout-with-zero-swap-max";
    if (madvise(page, PAGE_BYTES, MADV_PAGEOUT) != 0) goto out;
    step = "verify-zero-swap-current";
    if (read_number(swap_current_path, &current) != 0 || current != NO_SWAP_BYTES) goto out;
    step = "set-one-page-swap-max";
    if (write_text(swap_max_path, limit_text) != 0) goto out;
    step = "pageout-with-one-page-swap-max";
    if (madvise(page, PAGE_BYTES, MADV_PAGEOUT) != 0) goto out;
    step = "verify-one-page-swap-current";
    if (read_number(swap_current_path, &current) != 0 || current != SWAP_LIMIT_BYTES) goto out;
    step = "unmap-anonymous-page";
    if (munmap(page, PAGE_BYTES) != 0) goto out;
    page = MAP_FAILED;
    step = "verify-swap-charge-release";
    if (read_number(swap_current_path, &current) != 0 || current != 0) goto out;
    result = 0;
out:
    if (page != MAP_FAILED) (void)munmap(page, PAGE_BYTES);
    if (attached) (void)write_text(CGROUP_ROOT_PROCS, pid_text);
    if (created) (void)rmdir(CGROUP_PATH);
    if (result != 0) *failed_step = step;
    return result;
}

int main(void) {
    int rc = 1;
    int fd = -1;
    int active = 0;
    const char *memcg_failure = NULL;
    unlink(SWAP_FILE_PATH);
    fd = open(SWAP_FILE_PATH, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, OWNER_READ_WRITE);
    if (fd < 0) { fail("open"); goto out; }
    if (ftruncate(fd, SWAP_FILE_BYTES) != 0) { fail("ftruncate"); goto out; }
    if (write_all_pages(fd) != 0) { fail("initialize-pages"); goto out; }
    if (write_swap_header(fd) != 0) { fail("swap-header"); goto out; }
    if (close(fd) != 0) { fd = -1; fail("close"); goto out; }
    fd = -1;
    if (swapon(SWAP_FILE_PATH, 0) != 0) { fail("swapon"); goto out; }
    active = 1;
    if (proc_reports_active_swapfile() != 1) { fail("proc-swaps"); goto out; }
    if (memcg_pageout_smoke(&memcg_failure) != 0) { fail(memcg_failure); goto out; }
    if (swapoff(SWAP_FILE_PATH) != 0) { fail("swapoff"); goto out; }
    active = 0;
    if (unlink(SWAP_FILE_PATH) != 0) { fail("unlink"); goto out; }
    puts(PASS_LINE);
    rc = 0;
out:
    if (fd >= 0) close(fd);
    if (active) swapoff(SWAP_FILE_PATH);
    unlink(SWAP_FILE_PATH);
    return rc;
}
