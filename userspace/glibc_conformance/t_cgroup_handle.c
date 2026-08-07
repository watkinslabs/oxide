/* cgroup2 handle reopen: prove the 303 -> 304 path uses the anchor mount's
 * superblock, rather than an inode-private back-pointer. Run as guest root. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static const char CGROUP_ROOT[] = "/sys/fs/cgroup";
static const char CGROUP_CURRENT[] = ".";
static const char PASS_RESULT[] = "cgroup_handle: PASS";

enum {
    CGROUP_HANDLE_BYTES = sizeof(uint64_t),
    OPEN_FLAGS = O_RDONLY | O_DIRECTORY | O_CLOEXEC,
};

struct cgroup_handle {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[CGROUP_HANDLE_BYTES];
};

static int fail(const char *what) {
    perror(what);
    return 1;
}

int main(void) {
    struct cgroup_handle handle = { .handle_bytes = CGROUP_HANDLE_BYTES };
    struct stat before;
    struct stat after;
    int mount_id;
    int anchor = open(CGROUP_ROOT, OPEN_FLAGS);
    if (anchor < 0) return fail("open cgroup root");
    if (fstat(anchor, &before) != 0) { close(anchor); return fail("fstat cgroup root"); }
    if (name_to_handle_at(anchor, CGROUP_CURRENT, (struct file_handle *)&handle, &mount_id, 0) != 0) {
        close(anchor);
        return fail("name_to_handle_at cgroup root");
    }
    if (handle.handle_bytes != CGROUP_HANDLE_BYTES) {
        close(anchor);
        errno = EOVERFLOW;
        return fail("cgroup handle width");
    }
    int reopened = open_by_handle_at(anchor, (struct file_handle *)&handle, OPEN_FLAGS);
    if (reopened < 0) { close(anchor); return fail("open_by_handle_at cgroup root"); }
    if (fstat(reopened, &after) != 0) {
        close(reopened);
        close(anchor);
        return fail("fstat reopened cgroup root");
    }
    if (close(reopened) != 0 || close(anchor) != 0) return fail("close cgroup handles");
    if (before.st_dev != after.st_dev || before.st_ino != after.st_ino) {
        errno = ESTALE;
        return fail("reopened cgroup identity");
    }
    puts(PASS_RESULT);
    return 0;
}
