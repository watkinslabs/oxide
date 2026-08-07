/* Memory protection keys: pkey_alloc/free/mprotect (syscalls) + pkey_get/set
 * (PKRU/POR_EL0 register ops). Diff vs host glibc. If the CPU/kernel lacks PKU,
 * pkey_alloc returns -1/ENOSYS on both sides — still a clean match. */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>

static int signal_pkey;
static volatile sig_atomic_t signal_set;

static void change_pkey_in_handler(int sig) {
    (void)sig;
    signal_set = pkey_set(signal_pkey, PKEY_DISABLE_ACCESS);
}

int main(void) {
    int k = pkey_alloc(0, 0);
    if (k < 0) { printf("pkey unsupported errno=%d\n", errno); return 0; }

    int got0 = pkey_get(k);                 /* fresh key ⇒ no restrictions ⇒ 0 */
    int set = pkey_set(k, 0x1);             /* PKEY_DISABLE_ACCESS */
    int got1 = pkey_get(k);
    pkey_set(k, 0);                         /* restore before protecting */

    signal_pkey = k;
    struct sigaction sa = { .sa_handler = change_pkey_in_handler };
    sigemptyset(&sa.sa_mask);
    int sigact = sigaction(SIGUSR1, &sa, NULL);
    int raised = sigact == 0 ? raise(SIGUSR1) : -1;
    int sigafter = pkey_get(k);             /* sigreturn restores pre-handler PKRU */
    pkey_set(k, 0);                         /* preserve the later mapping check */

    void *p = mmap(0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int mp = pkey_mprotect(p, 4096, PROT_READ, k);
    int fr = pkey_free(k);

    printf("alloc_ok=%d get0=%d set=%d get1=%d sigact=%d raised=%d sigset=%d sigafter=%d mprotect=%d free=%d\n",
           k >= 0, got0, set, got1, sigact, raised, signal_set, sigafter, mp, fr);
    munmap(p, 4096);
    return 0;
}
