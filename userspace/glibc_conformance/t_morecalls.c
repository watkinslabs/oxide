/* flock, memfd_create, getresuid, copy_file_range — diff vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/mman.h>

int main(void) {
    int mf = memfd_create("t", 0);
    printf("memfd_ok=%d flock=%d\n", mf >= 0, flock(mf, LOCK_EX));

    uid_t r,e,s;
    printf("getresuid=%d eq=%d\n", getresuid(&r,&e,&s), (r==e && e==s) ? 1 : 0);

    char sp[]="/tmp/cfr_s_XXXXXX", dp[]="/tmp/cfr_d_XXXXXX";
    int sfd=mkstemp(sp), dfd=mkstemp(dp);
    if (write(sfd,"hello",5)!=5){printf("w fail\n");return 1;}
    lseek(sfd,0,SEEK_SET);
    printf("cfr=%zd\n", copy_file_range(sfd,NULL,dfd,NULL,5,0));
    close(sfd);close(dfd);unlink(sp);unlink(dp);close(mf);
    return 0;
}
