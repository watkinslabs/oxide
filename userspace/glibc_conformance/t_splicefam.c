/* tee/vmsplice/sync_file_range vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
int main(void){
    /* tee + vmsplice between pipes */
    int p1[2], p2[2];
    if(pipe(p1)||pipe(p2)){ perror("pipe"); return 1; }
    char data[]="hello world";
    struct iovec iov = { data, sizeof data - 1 };
    ssize_t w = vmsplice(p1[1], &iov, 1, 0);
    printf("vmsplice=%zd\n", w);
    ssize_t t = tee(p1[0], p2[1], 64, 0);
    printf("tee=%zd\n", t);
    /* read from p2 (the teed copy) */
    char buf[32]; memset(buf,0,sizeof buf);
    ssize_t r = read(p2[0], buf, sizeof buf - 1);
    printf("teed_read=%zd buf=%s\n", r, buf);
    /* drain p1 */
    r = read(p1[0], buf, sizeof buf - 1); printf("orig_read=%zd\n", r);

    /* sync_file_range on a real file */
    char path[]="/tmp/oxide_sfr_XXXXXX"; int fd=mkstemp(path);
    write(fd, "abcdefgh", 8);
    int sr = sync_file_range(fd, 0, 8, SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE|SYNC_FILE_RANGE_WAIT_AFTER);
    printf("sync_file_range=%d\n", sr);
    int sr2 = sync_file_range(-1, 0, 8, 0);  /* bad fd -> -1 EBADF */
    printf("sfr_badfd=%d\n", sr2);
    close(fd); unlink(path);
    close(p1[0]);close(p1[1]);close(p2[0]);close(p2[1]);
    return 0;
}
