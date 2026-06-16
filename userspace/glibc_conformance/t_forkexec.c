#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
int main(void){
    pid_t p = fork();
    /* clean env (no LD_LIBRARY_PATH) so the exec'd host binary uses host libs */
    if (p == 0) { char *a[]={"true",NULL}; char *e[]={"PATH=/usr/bin:/bin",NULL}; execve("/usr/bin/true", a, e); _exit(77); }
    int st=0; waitpid(p,&st,0);
    printf("exited=%d code=%d\n", WIFEXITED(st), WEXITSTATUS(st));
    return 0;
}
