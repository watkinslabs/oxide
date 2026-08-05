/* Exact target-side Landlock ABI negotiation contract. */
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define LL_CREATE_VERSION (1U << 0)
#define LL_TARGET_ABI 10

int main(void) {
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
                       LL_CREATE_VERSION);
    if (abi != LL_TARGET_ABI) {
        printf("landlock_abi: FAIL got=%ld expected=%d\n", abi,
               LL_TARGET_ABI);
        return 1;
    }
    printf("landlock_abi: PASS 10\n");
    return 0;
}
