/* statx() syscall wrapper for the old aarch64-linux-musl-cross musl
 * (predates the musl statx wrapper). systemd 259 calls statx()
 * unconditionally (assumes musl>=1.2.0). Linked into the arm systemd
 * build via the cross-file c_link_args. aarch64 __NR_statx = 291. */
#include <unistd.h>
#include <sys/syscall.h>
#ifndef SYS_statx
#define SYS_statx 291
#endif
int statx(int dirfd, const char *path, int flags, unsigned int mask, void *stxbuf)
{
    return syscall(SYS_statx, dirfd, path, flags, mask, stxbuf);
}
