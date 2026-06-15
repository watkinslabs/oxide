#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
int main(void){
    char *s = NULL;
    int n = asprintf(&s, "x=%d y=%s z=%.2f", 7, "mid", 1.5);
    printf("n=%d s=%s\n", n, s); free(s);
    return 0;
}
