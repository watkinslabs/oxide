/* a64l/l64a + alphasort/versionsort vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>

int main(void){
    /* round-trip a few values through l64a/a64l */
    long vs[] = {0, 1, 63, 64, 4095, 123456, 0x7fffffff, 0xABCDEF};
    for (size_t i=0;i<sizeof vs/sizeof vs[0];i++){
        char *e = l64a(vs[i]);
        char buf[8]; strcpy(buf, e);          /* l64a uses a static buffer */
        printf("l64a(%ld)=%s a64l=%ld\n", vs[i], buf, a64l(buf));
    }
    printf("a64l(zzzzzz)=%ld a64l(.)=%ld\n", a64l("zzzzzz"), a64l("."));

    /* alphasort / versionsort comparators over fake dirents */
    struct dirent a, b;
    strcpy(a.d_name, "file10"); strcpy(b.d_name, "file9");
    const struct dirent *pa=&a, *pb=&b;
    printf("alpha=%d vers=%d\n",
           alphasort(&pa,&pb) > 0,        /* "file10" > "file9" lexically */
           versionsort(&pa,&pb) < 0);     /* file10 > file9 numerically -> a<b false? */
    return 0;
}
