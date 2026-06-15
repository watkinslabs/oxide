#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
int main(void){
    printf("casecmp=%d ncasecmp=%d\n", strcasecmp("Hello","hello")==0, strncasecmp("ABCx","abcy",3)==0);
    char *d = strdup("duplicate"); printf("dup=%s\n", d); free(d);
    char *n = strndup("hello world", 5); printf("ndup=%s\n", n); free(n);
    return 0;
}
