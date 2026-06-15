#include <stdio.h>
#include <iconv.h>
#include <string.h>
int main(void){
    iconv_t cd = iconv_open("UTF-32LE","UTF-8");
    if(cd==(iconv_t)-1){ printf("open-fail\n"); return 1; }
    char in[]="Hi"; char out[32];
    char *ip=in; size_t il=2; char *op=out; size_t ol=32;
    size_t r = iconv(cd, &ip, &il, &op, &ol);
    printf("r=%zd consumed=%zu produced=%zu first=%d\n", (ssize_t)r, 2-il, 32-ol, out[0]);
    iconv_close(cd);
    return 0;
}
