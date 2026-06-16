/* mlock2/pivot_root/open_tree/move_mount/mount_setattr vs host glibc.
 * Unprivileged: exercises deterministic error paths (same uid+kernel). */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
extern int mlock2(const void*, size_t, unsigned);
extern int pivot_root(const char*, const char*);
extern int open_tree(int, const char*, unsigned);
extern int move_mount(int, const char*, int, const char*, unsigned);
extern int mount_setattr(int, const char*, unsigned, void*, size_t);
static void rep(const char*tag, int r){ printf("%s r=%d e=%d\n", tag, r, r<0?errno:0); }
int main(void){
    char buf[4096] __attribute__((aligned(4096)));
    errno=0; rep("mlock2_badflags", mlock2(buf, 16, 0x99));  /* EINVAL */
    errno=0; rep("pivot_root", pivot_root("/nonexistent_xyz","/nonexistent_xyz"));
    errno=0; rep("open_tree_enoent", open_tree(AT_FDCWD, "/nonexistent_xyz_123", 0));
    errno=0; rep("move_mount", move_mount(AT_FDCWD,"/nonexistent_a",AT_FDCWD,"/nonexistent_b",0));
    errno=0; rep("mount_setattr", mount_setattr(AT_FDCWD,"/nonexistent_xyz",0,(void*)0,0));
    return 0;
}
