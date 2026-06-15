#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
int main(void){
    char buf[PATH_MAX];
    char *r = realpath("/tmp/../tmp", buf);
    printf("rp=%s ok=%d\n", r?r:"null", r!=NULL);
    return 0;
}
