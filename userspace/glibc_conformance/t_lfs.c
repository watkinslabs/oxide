/* LFS / *64 + pread/pwrite/creat audit vs host glibc. Real syscalls on a temp
   file (the harness runs our libc against the host kernel). */
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int main(void){
    const char *p = "/tmp/oxide_lfs_test.dat";
    int fd = creat(p, 0644);
    const char *msg = "hello LFS world";
    pwrite(fd, msg, 15, 0);
    pwrite(fd, "XYZ", 3, 5);          /* overwrite at offset 5 */
    close(fd);

    struct stat64 st;
    int r = stat64(p, &st);
    printf("stat64 r=%d size=%lld\n", r, (long long)st.st_size);

    fd = open64(p, O_RDONLY);
    char buf[32];
    ssize_t n = pread64(fd, buf, 15, 0); buf[n] = 0;
    printf("pread n=%zd buf=%s\n", n, buf);
    off_t pos = lseek64(fd, 5, SEEK_SET);
    n = read(fd, buf, 3); buf[n] = 0;
    printf("lseek pos=%lld read=%s\n", (long long)pos, buf);
    struct stat64 fs;
    fstat64(fd, &fs);
    printf("fstat64 size=%lld isreg=%d\n", (long long)fs.st_size, S_ISREG(fs.st_mode)!=0);
    close(fd);
    unlink(p);
    return 0;
}
