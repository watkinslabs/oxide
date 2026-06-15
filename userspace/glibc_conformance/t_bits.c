#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <strings.h>
int main(void){
    printf("ffs0=%d ffs1=%d ffs8=%d ffs96=%d\n", ffs(0), ffs(1), ffs(8), ffs(96));
    printf("ffsl=%d ffsll=%d\n", ffsl(0x100000000L), ffsll(0x8000000000000000ULL));
    char b[8] = "abcdefg";
    bzero(b+2, 3);
    printf("bzero=%d%d%d%d%d%d\n", b[0],b[1],b[2],b[3],b[4],b[5]);
    char dst[8]; bcopy("XYZ", dst, 3); dst[3]=0;
    printf("bcopy=%s\n", dst);
    char f[] = "secret";
    memfrob(f, 6); printf("frob1=%d", f[0]);
    memfrob(f, 6); printf(" frob2=%s\n", f); /* twice restores */
    return 0;
}
