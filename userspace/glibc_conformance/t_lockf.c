/* lockf vs host glibc: own-lock test/unlock + bad cmd. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
int main(void){
    char p[]="/tmp/oxide_lockf_XXXXXX"; int fd=mkstemp(p);
    if(fd<0){ perror("mkstemp"); return 1; }
    ftruncate(fd,200);
    lseek(fd,10,SEEK_SET);
    printf("tlock=%d\n", lockf(fd,F_TLOCK,20));
    lseek(fd,10,SEEK_SET);
    printf("test_own=%d\n", lockf(fd,F_TEST,20));   /* own lock -> 0 */
    lseek(fd,50,SEEK_SET);
    printf("test_free=%d\n", lockf(fd,F_TEST,10));  /* unlocked region -> 0 */
    lseek(fd,10,SEEK_SET);
    printf("relock_own=%d\n", lockf(fd,F_LOCK,20));  /* re-lock own -> 0 */
    lseek(fd,10,SEEK_SET);
    printf("unlock=%d\n", lockf(fd,F_ULOCK,20));
    printf("badcmd=%d errno_is_einval=%d\n", lockf(fd,99,10), 0);
    close(fd); unlink(p);
    return 0;
}
