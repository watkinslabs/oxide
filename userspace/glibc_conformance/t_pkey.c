/* Memory protection keys: pkey_alloc/free/mprotect (syscalls) + pkey_get/set
 * (PKRU/POR_EL0 register ops). Diff vs host glibc. If the CPU/kernel lacks PKU,
 * pkey_alloc returns -1/ENOSYS on both sides — still a clean match. */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>

int main(void) {
    int k = pkey_alloc(0, 0);
    if (k < 0) { printf("pkey unsupported errno=%d\n", errno); return 0; }

    int got0 = pkey_get(k);                 /* fresh key ⇒ no restrictions ⇒ 0 */
    int set = pkey_set(k, 0x1);             /* PKEY_DISABLE_ACCESS */
    int got1 = pkey_get(k);
    pkey_set(k, 0);                         /* restore before protecting */

    void *p = mmap(0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int mp = pkey_mprotect(p, 4096, PROT_READ, k);
    int fr = pkey_free(k);

    printf("alloc_ok=%d get0=%d set=%d get1=%d mprotect=%d free=%d\n",
           k >= 0, got0, set, got1, mp, fr);
    munmap(p, 4096);
    return 0;
}
