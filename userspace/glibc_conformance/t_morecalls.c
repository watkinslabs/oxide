/* flock, memfd_create, getresuid, copy_file_range, execveat, sockatmark,
 * isfdtype — diff vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

static char *CLEAN[] = { "PATH=/usr/bin:/bin", NULL };

int main(void) {
    int mf = memfd_create("t", 0);
    printf("memfd_ok=%d flock=%d\n", mf >= 0, flock(mf, LOCK_EX));

    uid_t r=0,e=0,s=0;
    printf("getresuid=%d eq=%d\n", getresuid(&r,&e,&s), (r==e && e==s) ? 1 : 0);

    char sp[]="/tmp/cfr_s_XXXXXX", dp[]="/tmp/cfr_d_XXXXXX";
    int sfd=mkstemp(sp), dfd=mkstemp(dp);
    if (write(sfd,"hello",5)!=5){printf("w fail\n");return 1;}
    lseek(sfd,0,SEEK_SET);
    printf("cfr=%zd\n", copy_file_range(sfd,NULL,dfd,NULL,5,0));
    close(sfd);close(dfd);unlink(sp);unlink(dp);close(mf);

    /* isfdtype: a socket fd is S_IFSOCK, not S_IFREG; a regular file the reverse. */
    int sk = socket(AF_INET, SOCK_STREAM, 0);
    char rp[]="/tmp/ift_XXXXXX"; int rfd = mkstemp(rp);
    printf("isfdtype sock=%d notreg=%d reg=%d\n",
        isfdtype(sk, S_IFSOCK), isfdtype(sk, S_IFREG), isfdtype(rfd, S_IFREG));

    /* sockatmark: a fresh socketpair endpoint is not at the OOB mark. */
    int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    printf("sockatmark=%d\n", sockatmark(sv[0]));
    close(sk); close(rfd); unlink(rp); close(sv[0]); close(sv[1]);

    /* execveat: exec /bin/echo via a dirfd, stdout redirected to a temp file. */
    char ep[]="/tmp/eat_XXXXXX"; int efd = mkstemp(ep); close(efd);
    int dirfd = open("/bin", O_RDONLY|O_DIRECTORY);
    pid_t pid = fork();
    if (pid == 0) {
        int o = open(ep, O_WRONLY|O_TRUNC); dup2(o, 1); close(o);
        execveat(dirfd, "echo", (char*[]){"echo","eat-ok",NULL}, CLEAN, 0);
        _exit(127);
    }
    int st = 0; waitpid(pid, &st, 0);
    char eb[16] = {0}; int ef = open(ep, O_RDONLY); ssize_t en = read(ef, eb, sizeof eb - 1); close(ef);
    if (en > 0 && eb[en-1] == '\n') eb[en-1] = 0;
    printf("execveat exit0=%d out=%s\n", WIFEXITED(st) && WEXITSTATUS(st)==0, eb);
    close(dirfd); unlink(ep);
    return 0;
}
