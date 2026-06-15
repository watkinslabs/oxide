#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
int main(void){
    char b[8]; char *e = stpncpy(b, "hi", 8); printf("stpncpy_off=%ld pad0=%d\n", e-b, b[2]==0&&b[7]==0);
    printf("memrchr=%ld\n", (long)((char*)memrchr("a/b/c",'/',5) - "a/b/c"));
    char hay[]="hello world"; printf("memmem=%ld\n", (long)((char*)memmem(hay,11,"wor",3) - hay));
    return 0;
}
