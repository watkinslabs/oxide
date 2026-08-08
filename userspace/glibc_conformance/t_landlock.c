/* Landlock slots 444-446 live user-copy and admission corpus. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define LL_CREATE_VERSION  (1U << 0)
#define LL_ACCESS_FS_EXECUTE (1ULL << 0)
#define LL_ACCESS_NET_BIND_TCP (1ULL << 0)
#define LL_RULE_PATH_BENEATH 1
#define LL_RULE_NET_PORT 2

struct ll_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
    uint64_t scoped;
    uint64_t quiet_access_fs;
    uint64_t quiet_access_net;
    uint64_t quiet_scoped;
};

struct ll_path_beneath_attr {
    uint64_t allowed_access;
    int32_t parent_fd;
} __attribute__((packed));

struct ll_net_port_attr {
    uint64_t allowed_access;
    uint64_t port;
};

_Static_assert(sizeof(struct ll_ruleset_attr) == 48, "ruleset ABI layout");
_Static_assert(sizeof(struct ll_path_beneath_attr) == 12, "path ABI layout");
_Static_assert(sizeof(struct ll_net_port_attr) == 16, "network ABI layout");

static long create_ruleset(const void *attr, size_t size, unsigned int flags) {
    return syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

static long add_rule(int fd, int type, const void *attr, unsigned int flags) {
    return syscall(SYS_landlock_add_rule, fd, type, attr, flags);
}

static long restrict_self(int fd, unsigned int flags) {
    return syscall(SYS_landlock_restrict_self, fd, flags);
}

static void show(const char *label, long rc) {
    printf("%s rc=%ld errno=%d\n", label, rc < 0 ? -1L : 0L,
           rc < 0 ? errno : 0);
}

int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return 2;
    unsigned char *map = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) return 2;
    if (mprotect(map + page, (size_t)page, PROT_NONE) != 0) return 2;

    errno = 0;
    long abi = create_ruleset(NULL, 0, LL_CREATE_VERSION);
    printf("abi available=%d errno=%d\n", abi >= 1, abi < 0 ? errno : 0);

    errno = 0;
    show("create_query_bad_attr",
         create_ruleset(map + page - 4, 0, LL_CREATE_VERSION));
    errno = 0;
    show("create_null", create_ruleset(NULL, 0, 0));
    errno = 0;
    show("create_short", create_ruleset(map, 7, 0));

    memset(map + page - 4, 0, 4);
    errno = 0;
    show("create_head_fault", create_ruleset(map + page - 4, 8, 0));

    struct ll_ruleset_attr *guarded =
        (struct ll_ruleset_attr *)(map + page - sizeof(*guarded));
    memset(guarded, 0, sizeof(*guarded));
    guarded->handled_access_fs = LL_ACCESS_FS_EXECUTE;
    errno = 0;
    show("create_tail_fault", create_ruleset(guarded, sizeof(*guarded) + 1, 0));

    struct {
        struct ll_ruleset_attr attr;
        unsigned char tail;
    } extended = { .attr = { .handled_access_fs = LL_ACCESS_FS_EXECUTE }, .tail = 0 };
    errno = 0;
    long extended_fd = create_ruleset(&extended, sizeof(extended), 0);
    show("create_zero_tail", extended_fd);
    if (extended_fd >= 0) close((int)extended_fd);
    extended.tail = 1;
    errno = 0;
    show("create_nonzero_tail", create_ruleset(&extended, sizeof(extended), 0));

    struct ll_ruleset_attr attr = { .handled_access_fs = LL_ACCESS_FS_EXECUTE };
    long fd = create_ruleset(&attr, sizeof(attr.handled_access_fs), 0);
    if (fd < 0) {
        show("create_setup", fd);
        munmap(map, (size_t)page * 2);
        return 1;
    }
    show("create_setup", fd);

    errno = 0;
    show("add_flags_before_fd", add_rule(-1, LL_RULE_PATH_BENEATH,
                                          map + page - 4, 1U << 31));
    errno = 0;
    show("add_fd_before_copy", add_rule(-1, LL_RULE_PATH_BENEATH,
                                         map + page - 4, 0));
    errno = 0;
    show("add_type_before_copy", add_rule((int)fd, 99, map + page - 4, 0));

    uint64_t *partial = (uint64_t *)(map + page - sizeof(uint64_t));
    *partial = LL_ACCESS_FS_EXECUTE;
    errno = 0;
    show("add_path_fault", add_rule((int)fd, LL_RULE_PATH_BENEATH, partial, 0));
    *partial = LL_ACCESS_NET_BIND_TCP;
    errno = 0;
    show("add_net_fault", add_rule((int)fd, LL_RULE_NET_PORT, partial, 0));

    /* A descriptor with no mount behind it names no hierarchy: a pipe end and
       the ruleset fd itself are both EBADFD, not EBADF and not success. */
    int pipe_fds[2];
    if (pipe(pipe_fds) == 0) {
        struct ll_path_beneath_attr pb = {
            .allowed_access = LL_ACCESS_FS_EXECUTE, .parent_fd = pipe_fds[0] };
        errno = 0;
        show("add_path_pipe_fd", add_rule((int)fd, LL_RULE_PATH_BENEATH, &pb, 0));
        close(pipe_fds[0]);
        close(pipe_fds[1]);
    }
    struct ll_path_beneath_attr self_pb = {
        .allowed_access = LL_ACCESS_FS_EXECUTE, .parent_fd = (int)fd };
    errno = 0;
    show("add_path_ruleset_fd", add_rule((int)fd, LL_RULE_PATH_BENEATH, &self_pb, 0));

    errno = 0;
    show("restrict_privilege_before_flags", restrict_self(-1, 1U << 31));
    errno = 0;
    show("set_no_new_privs", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    errno = 0;
    show("restrict_flags_before_fd", restrict_self(-1, 1U << 31));
    errno = 0;
    show("restrict_bad_fd", restrict_self(-1, 0));
    errno = 0;
    show("restrict_valid", restrict_self((int)fd, 0));

    close((int)fd);
    munmap(map, (size_t)page * 2);
    return abi >= 1 ? 0 : 1;
}
