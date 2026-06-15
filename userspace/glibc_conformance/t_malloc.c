#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){
    char *p = malloc(100); strcpy(p,"alloc-ok"); printf("%s\n", p);
    p = realloc(p, 2000); strcat(p, "-realloc"); printf("%s\n", p);
    free(p);
    int *a = calloc(16, sizeof(int)); int s=0; for(int i=0;i<16;i++) s+=a[i]; printf("calloc-zero=%d\n", s);
    a[0]=7; a[15]=11; printf("sum=%d\n", a[0]+a[15]); free(a);
    return 0;
}
