/* gnu_get_libc_version/release identity API properties vs host glibc. */
#define _GNU_SOURCE
#include <ctype.h>
#include <gnu/libc-version.h>
#include <stdio.h>
#include <string.h>

int main(void){
    const char *v = gnu_get_libc_version();
    const char *r = gnu_get_libc_release();
    int shape = v && isdigit((unsigned char)v[0]) && strchr(v, '.') != NULL;
    printf("version_shape=%d release_stable=%d release_nonempty=%d\n",
           shape, r && strcmp(r, "stable") == 0, r && r[0] != 0);
    return 0;
}
