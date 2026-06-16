/* dladdr / dladdr1 over &main's object. vs host glibc (boolean, addresses differ). */
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
int main(void) {
    Dl_info info;
    int r = dladdr((void *)&main, &info);
    printf("dladdr=%d fbase_set=%d\n", r != 0, info.dli_fbase != NULL);
    Dl_info i2; void *extra = (void *)1;
    int r2 = dladdr1((void *)&main, &i2, &extra, 0);
    printf("dladdr1=%d extra_untouched=%d\n", r2 != 0, extra == (void *)1);
    printf("dlerror=%d\n", dlerror() == NULL);
    return 0;
}
