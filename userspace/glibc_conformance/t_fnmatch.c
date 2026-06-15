#include <stdio.h>
#include <fnmatch.h>
int main(void){
    printf("%d %d %d %d\n",
        fnmatch("*.c","foo.c",0)==0, fnmatch("*.c","foo.h",0)==0,
        fnmatch("f?o","foo",0)==0, fnmatch("[a-c]*","bar",0)==0);
    return 0;
}
