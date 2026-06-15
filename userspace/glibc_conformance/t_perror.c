#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
int main(void){
    dup2(1, 2); /* route stderr to stdout so the harness captures perror */
    errno = 2;  /* ENOENT */
    perror("myprog");
    errno = 13; /* EACCES */
    perror(NULL);
    fflush(NULL);
    printf("se22=%s\n", strerror(22));
    return 0;
}
