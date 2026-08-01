#include <stdio.h>
#include <stdlib.h>
/* `<linux/limits.h>` before `<limits.h>`: under `--sysroot`, the AArch64 cross
   compiler does not reach GCC's own `limits.h`, so glibc's never defines
   PATH_MAX. The UAPI header is present in every sysroot and defines the same
   value the host resolves to. */
#include <linux/limits.h>
#include <limits.h>
int main(void){
    char buf[PATH_MAX];
    char *r = realpath("/tmp/../tmp", buf);
    printf("rp=%s ok=%d\n", r?r:"null", r!=NULL);
    return 0;
}
