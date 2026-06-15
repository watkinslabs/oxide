#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
int main(void){
    errno = 0;
    int fd = open("/nonexistent/path/xyz", O_RDONLY);
    printf("fd=%d errno=%d is_enoent=%d\n", fd, errno, errno==ENOENT);
    const char *m = strerror(ENOENT); printf("strerror=%s\n", m);
    const char *m2 = strerror(EINVAL); printf("einval=%s\n", m2);
    return 0;
}
