/* Linux zram lifecycle corpus.  Run in an ephemeral root guest with --live. */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/types.h>
#include <unistd.h>

static const char ZRAM_CONTROL_DIRECTORY[] = "/sys/class/zram-control";
static const char ZRAM_CONTROL_HOT_ADD[] = "/sys/class/zram-control/hot_add";
static const char ZRAM_CONTROL_HOT_REMOVE[] = "/sys/class/zram-control/hot_remove";
static const char ZRAM_NAME_PREFIX[] = "zram";
static const char ZRAM_DEVICE_DIRECTORY[] = "/dev";
static const char ZRAM_BLOCK_DIRECTORY[] = "/sys/block";
static const char PROC_SWAPS[] = "/proc/swaps";
static const char SWAP_MAGIC[] = "SWAPSPACE2";
static const char LIVE_ARGUMENT[] = "--live";
static const char PASS_RESULT[] = "zram_lifecycle: PASS sysfs swap swapon swapoff reset";
static const char RESET_REQUEST[] = "1\n";
static const char DISKSIZE_REQUEST[] = "16777216\n";
static const char INITIALIZED_STATE[] = "1\n";

enum {
    PATH_BUFFER_BYTES = 256,
    PROC_LINE_BYTES = 512,
    ZRAM_INDEX_TEXT_BYTES = sizeof("4294967295"),
    ZRAM_NAME_BYTES = sizeof(ZRAM_NAME_PREFIX) - 1 + ZRAM_INDEX_TEXT_BYTES,
    SWAP_PAGE_BYTES = 4096,
    ZRAM_DISKSIZE_BYTES = 16 * 1024 * 1024,
    SWAP_HEADER_VERSION_OFFSET = 1024,
    SWAP_HEADER_LAST_PAGE_OFFSET = SWAP_HEADER_VERSION_OFFSET + sizeof(uint32_t),
    SWAP_HEADER_BAD_PAGE_COUNT_OFFSET = SWAP_HEADER_LAST_PAGE_OFFSET + sizeof(uint32_t),
    SWAP_MAGIC_BYTES = sizeof(SWAP_MAGIC) - 1,
    SWAP_HEADER_MAGIC_OFFSET = SWAP_PAGE_BYTES - SWAP_MAGIC_BYTES,
    SWAPSPACE2_VERSION = 1,
    SWAP_HEADER_BAD_PAGE_COUNT_NONE = 0,
    ZRAM_SWAP_LAST_PAGE = ZRAM_DISKSIZE_BYTES / SWAP_PAGE_BYTES - 1,
    ZRAM_ATTRIBUTE_FIELD_MINIMUM = 1,
    MM_STAT_FIELD_COUNT = 9,
    IO_STAT_FIELD_COUNT = 4,
    ZRAM_LIVE_ARGUMENT_COUNT = 2,
    ROOT_UID = 0,
    SWAP_FLAGS_NONE = 0,
    FIRST_DEVICE_OFFSET = 0,
    DECIMAL_BASE = 10,
};

struct zram_device {
    uint32_t index;
    char index_text[ZRAM_INDEX_TEXT_BYTES];
    char name[ZRAM_NAME_BYTES];
    char device[PATH_BUFFER_BYTES];
    char block_directory[PATH_BUFFER_BYTES];
};

static int join_path(char *path, size_t capacity, const char *directory, const char *leaf) {
    int length = snprintf(path, capacity, "%s/%s", directory, leaf);
    return length > 0 && (size_t)length < capacity ? 0 : -1;
}

static int attribute_path(const struct zram_device *zram, char *path, size_t capacity, const char *attribute) {
    return join_path(path, capacity, zram->block_directory, attribute);
}

static int write_text(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t length = strlen(text);
    ssize_t written = write(fd, text, length);
    int saved_errno = errno;
    if (close(fd) != 0 && written == (ssize_t)length) saved_errno = errno;
    errno = saved_errno;
    return written == (ssize_t)length ? 0 : -1;
}

static int read_text(const char *path, char *text, size_t capacity) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t length = read(fd, text, capacity - 1);
    int saved_errno = errno;
    if (close(fd) != 0 && length >= 0) saved_errno = errno;
    errno = saved_errno;
    if (length < 0) return -1;
    text[length] = '\0';
    return 0;
}

static int attribute_has_fields(const struct zram_device *zram, const char *attribute, unsigned int required_fields) {
    char path[PATH_BUFFER_BYTES];
    char text[PROC_LINE_BYTES];
    char *cursor;
    unsigned int fields = 0;
    if (attribute_path(zram, path, sizeof(path), attribute) != 0 || read_text(path, text, sizeof(text)) != 0) return -1;
    cursor = text;
    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n') cursor++;
        if (*cursor == '\0') break;
        fields++;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' && *cursor != '\n') cursor++;
    }
    return fields >= required_fields ? 0 : -1;
}

static int validate_attributes(const struct zram_device *zram) {
    char path[PATH_BUFFER_BYTES];
    char text[PROC_LINE_BYTES];
    static const char *const basic_attributes[] = {
        "disksize", "initstate", "comp_algorithm", "mm_stat", "io_stat",
    };
    size_t count = sizeof(basic_attributes) / sizeof(basic_attributes[0]);
    for (size_t index = 0; index < count; index++) {
        if (attribute_path(zram, path, sizeof(path), basic_attributes[index]) != 0
            || read_text(path, text, sizeof(text)) != 0) return -1;
    }
    if (attribute_path(zram, path, sizeof(path), "reset") != 0 || access(path, W_OK) != 0) return -1;
    if (attribute_has_fields(zram, "comp_algorithm", ZRAM_ATTRIBUTE_FIELD_MINIMUM) != 0
        || attribute_has_fields(zram, "mm_stat", MM_STAT_FIELD_COUNT) != 0
        || attribute_has_fields(zram, "io_stat", IO_STAT_FIELD_COUNT) != 0) return -1;
    return 0;
}

static int reset_zram(const struct zram_device *zram) {
    char path[PATH_BUFFER_BYTES];
    if (attribute_path(zram, path, sizeof(path), "reset") != 0) return -1;
    return write_text(path, RESET_REQUEST);
}

static int configure_disksize(const struct zram_device *zram) {
    char path[PATH_BUFFER_BYTES];
    char text[PROC_LINE_BYTES];
    char *end = NULL;
    unsigned long long size;
    if (attribute_path(zram, path, sizeof(path), "disksize") != 0 || write_text(path, DISKSIZE_REQUEST) != 0
        || read_text(path, text, sizeof(text)) != 0) return -1;
    errno = 0;
    size = strtoull(text, &end, DECIMAL_BASE);
    if (errno != 0 || end == text || size != ZRAM_DISKSIZE_BYTES) return -1;
    if (attribute_path(zram, path, sizeof(path), "initstate") != 0 || read_text(path, text, sizeof(text)) != 0) return -1;
    return strcmp(text, INITIALIZED_STATE) == 0 ? 0 : -1;
}

static int write_swap_header(const struct zram_device *zram) {
    uint8_t page[SWAP_PAGE_BYTES] = {0};
    uint32_t version = SWAPSPACE2_VERSION;
    uint32_t last_page = ZRAM_SWAP_LAST_PAGE;
    uint32_t bad_page_count = SWAP_HEADER_BAD_PAGE_COUNT_NONE;
    int fd = open(zram->device, O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    memcpy(page + SWAP_HEADER_VERSION_OFFSET, &version, sizeof(version));
    memcpy(page + SWAP_HEADER_LAST_PAGE_OFFSET, &last_page, sizeof(last_page));
    memcpy(page + SWAP_HEADER_BAD_PAGE_COUNT_OFFSET, &bad_page_count, sizeof(bad_page_count));
    memcpy(page + SWAP_HEADER_MAGIC_OFFSET, SWAP_MAGIC, SWAP_MAGIC_BYTES);
    ssize_t written = pwrite(fd, page, sizeof(page), FIRST_DEVICE_OFFSET);
    int saved_errno = errno;
    if (fsync(fd) != 0 && written == (ssize_t)sizeof(page)) saved_errno = errno;
    if (close(fd) != 0 && written == (ssize_t)sizeof(page)) saved_errno = errno;
    errno = saved_errno;
    return written == (ssize_t)sizeof(page) ? 0 : -1;
}

static int proc_swaps_has_zram(const struct zram_device *zram) {
    char line[PROC_LINE_BYTES];
    char device[PATH_BUFFER_BYTES];
    FILE *swaps = fopen(PROC_SWAPS, "re");
    if (swaps == NULL) return -1;
    while (fgets(line, sizeof(line), swaps) != NULL) {
        if (sscanf(line, "%255s", device) == 1 && strcmp(device, zram->device) == 0) {
            int close_result = fclose(swaps);
            return close_result == 0 ? 1 : -1;
        }
    }
    if (fclose(swaps) != 0) return -1;
    return 0;
}

static int parse_zram_index(const char *text, uint32_t *index) {
    char *end = NULL;
    unsigned long parsed;
    errno = 0;
    parsed = strtoul(text, &end, DECIMAL_BASE);
    if (errno != 0 || end == text || parsed > UINT32_MAX) return -1;
    while (isspace((unsigned char)*end)) end++;
    if (*end != '\0') { errno = EINVAL; return -1; }
    *index = (uint32_t)parsed;
    return 0;
}

static int hot_remove_zram(const struct zram_device *zram);

static int set_device_paths(struct zram_device *zram) {
    int index_length = snprintf(zram->index_text, sizeof(zram->index_text), "%" PRIu32, zram->index);
    int name_length;
    if (index_length <= 0 || (size_t)index_length >= sizeof(zram->index_text)) return -1;
    name_length = snprintf(zram->name, sizeof(zram->name), "%s%s", ZRAM_NAME_PREFIX, zram->index_text);
    if (name_length <= 0 || (size_t)name_length >= sizeof(zram->name)
        || join_path(zram->device, sizeof(zram->device), ZRAM_DEVICE_DIRECTORY, zram->name) != 0
        || join_path(zram->block_directory, sizeof(zram->block_directory), ZRAM_BLOCK_DIRECTORY, zram->name) != 0) return -1;
    return 0;
}

static int hot_add_zram(struct zram_device *zram) {
    char text[PROC_LINE_BYTES];
    if (read_text(ZRAM_CONTROL_HOT_ADD, text, sizeof(text)) != 0
        || parse_zram_index(text, &zram->index) != 0) return -1;
    if (set_device_paths(zram) != 0) {
        int saved_errno = errno;
        (void)hot_remove_zram(zram);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int hot_remove_zram(const struct zram_device *zram) {
    char request[ZRAM_INDEX_TEXT_BYTES + sizeof("\n")];
    int length = snprintf(request, sizeof(request), "%s\n", zram->index_text);
    if (length <= 0 || (size_t)length >= sizeof(request)) return -1;
    return write_text(ZRAM_CONTROL_HOT_REMOVE, request);
}

static void report_failure(const char *step) {
    printf("zram_lifecycle: FAIL %s errno=%d\n", step, errno);
}

int main(int argc, char **argv) {
    int active = 0;
    int created = 0;
    int result = 1;
    int saved_errno = 0;
    struct zram_device zram = {0};
    const char *step = "arguments";
    if (argc != ZRAM_LIVE_ARGUMENT_COUNT || strcmp(argv[1], LIVE_ARGUMENT) != 0) {
        puts("zram_lifecycle: SKIP invoke with --live in an ephemeral root guest");
        return 0;
    }
    if (geteuid() != ROOT_UID) { report_failure("root-required"); return 1; }
    if (access(ZRAM_CONTROL_DIRECTORY, R_OK | X_OK) != 0) { report_failure("zram-control"); return 1; }
    step = "hot-add";
    if (hot_add_zram(&zram) != 0) goto out;
    created = 1;
    step = "zram-device";
    if (access(zram.device, R_OK | W_OK) != 0) goto out;
    step = "validate-attributes";
    if (validate_attributes(&zram) != 0) goto out;
    step = "configure-disksize";
    if (configure_disksize(&zram) != 0) goto out;
    step = "write-swap-header";
    if (write_swap_header(&zram) != 0) goto out;
    step = "swapon";
    if (swapon(zram.device, SWAP_FLAGS_NONE) != 0) goto out;
    active = 1;
    step = "proc-swaps-active";
    if (proc_swaps_has_zram(&zram) != 1) goto out;
    step = "swapoff";
    if (swapoff(zram.device) != 0) goto out;
    active = 0;
    step = "proc-swaps-inactive";
    if (proc_swaps_has_zram(&zram) != 0) goto out;
    step = "reset-after-swapoff";
    if (reset_zram(&zram) != 0) goto out;
    step = "hot-remove";
    if (hot_remove_zram(&zram) != 0) goto out;
    created = 0;
    if (puts(PASS_RESULT) == EOF) return 1;
    return 0;
out:
    saved_errno = errno;
    if (active) (void)swapoff(zram.device);
    if (created) {
        (void)reset_zram(&zram);
        (void)hot_remove_zram(&zram);
    }
    errno = saved_errno;
    report_failure(step);
    return result;
}
