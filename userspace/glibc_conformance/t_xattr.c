/* xattr: set a user.* attr on a temp file, get it back, list it, remove it.
 * (tmpfs/ext4 in the test sysroot supports user xattrs.) */
#include <stdio.h>
#include <stdlib.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    char path[] = "/tmp/t_xattr_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { printf("mkstemp fail\n"); return 1; }

    int s = setxattr(path, "user.test", "hi", 2, 0);
    printf("set=%d\n", s);
    char buf[16] = {0};
    long g = getxattr(path, "user.test", buf, sizeof buf);
    printf("get=%ld val=%.*s\n", g, (int)(g > 0 ? g : 0), buf);
    long l = listxattr(path, NULL, 0);   /* size query */
    printf("list_sz_ok=%d\n", l >= 9 ? 1 : 0);  /* "user.test\0" = 10 */
    int r = removexattr(path, "user.test");
    printf("rm=%d after=%ld\n", r, getxattr(path, "user.test", buf, sizeof buf));

    close(fd); unlink(path);
    return 0;
}
