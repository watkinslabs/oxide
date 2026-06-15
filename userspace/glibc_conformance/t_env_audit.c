/* Environment functions audit vs host glibc: setenv overwrite flag, putenv
   (with and without '='), unsetenv, invalid names + errno. */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

static void g(const char *k){ char *v = getenv(k); printf("get %s=%s\n", k, v?v:"(null)"); }

int main(void){
    int r;
    r = setenv("AUDIT_A", "one", 1);   printf("setA r=%d\n", r); g("AUDIT_A");
    r = setenv("AUDIT_A", "two", 0);   printf("noovr r=%d\n", r); g("AUDIT_A"); /* keeps "one" */
    r = setenv("AUDIT_A", "three", 1); printf("ovr r=%d\n", r); g("AUDIT_A");   /* now "three" */
    r = setenv("AUDIT_B", "", 1);      printf("empty r=%d\n", r); g("AUDIT_B"); /* "" */

    /* invalid names */
    errno=0; r = setenv("BAD=NAME", "x", 1); printf("badname r=%d err=%d\n", r, errno);
    errno=0; r = setenv("", "x", 1);         printf("emptyname r=%d err=%d\n", r, errno);

    /* putenv */
    static char p1[] = "AUDIT_C=cval";
    r = putenv(p1); printf("putC r=%d\n", r); g("AUDIT_C");
    static char p2[] = "AUDIT_A=fromputenv";
    r = putenv(p2); printf("putA r=%d\n", r); g("AUDIT_A"); /* replaces */

    /* unsetenv */
    r = unsetenv("AUDIT_A"); printf("unsetA r=%d\n", r); g("AUDIT_A");
    r = unsetenv("NOPE_XYZ"); printf("unsetmissing r=%d\n", r); /* success */
    errno=0; r = unsetenv("BAD=X"); printf("unsetbad r=%d err=%d\n", r, errno);

    g("PATH_THAT_DOES_NOT_EXIST_123");
    return 0;
}
