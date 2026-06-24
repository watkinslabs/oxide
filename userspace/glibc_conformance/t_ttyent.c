/* ttyent DB (/etc/ttys usually absent on Linux → NULL). vs host glibc. */
#define _GNU_SOURCE
#include <ttyent.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
    int s = setttyent();
    struct ttyent *e = getttyent();
    struct ttyent *n = getttynam("console");
    int en = endttyent();
    printf("set=%d ent_null=%d nam_null=%d end=%d\n", s, e == NULL, n == NULL, en);
    printf("ttyslot=%d\n", ttyslot());
    return 0;
}
