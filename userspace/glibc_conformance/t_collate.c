#include <stdio.h>
#include <string.h>
int main(void){
    printf("coll_ab=%d coll_ba=%d coll_eq=%d\n",
           strcoll("abc","abd") < 0, strcoll("xyz","abc") > 0, strcoll("dup","dup"));
    char buf[16];
    size_t n = strxfrm(buf, "hello", sizeof buf);
    printf("xfrm_len=%zu xfrm=%s\n", n, buf);
    /* short buffer: only the return (source length) is defined by C11
       7.24.4.5 — dest contents are indeterminate when ret >= n, so do not
       read them. */
    char small[3];
    size_t n2 = strxfrm(small, "world", sizeof small);
    printf("xfrm_short_len=%zu\n", n2);
    return 0;
}
