#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
int main(void){
    printf("ascii=%d%d toascii=%d\n", isascii('A')!=0, isascii(200)!=0, toascii(0xC1));
    printf("up=%d lo=%d\n", toupper('a'), tolower('Z'));
    printf("isctype=%d %d %d\n", isctype('A', _ISupper), isctype('5', _ISdigit|_ISxdigit), isctype(200, _ISalpha));
    return 0;
}
