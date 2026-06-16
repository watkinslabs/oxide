/* eaccess/euidaccess, sigisemptyset/sigorset/sigandset, __fpclassify. vs host. */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <float.h>

int main(void) {
    printf("eaccess_root=%d eaccess_bad=%d euidaccess=%d\n",
           eaccess("/", R_OK) == 0, eaccess("/no_such_xyz", F_OK) != 0, euidaccess("/", X_OK) == 0);

    sigset_t a, b, o, n;
    sigemptyset(&a);
    printf("isempty_empty=%d\n", sigisemptyset(&a));
    sigaddset(&a, SIGUSR1);
    printf("isempty_full=%d\n", sigisemptyset(&a) == 0);
    sigemptyset(&b); sigaddset(&b, SIGUSR2);
    sigorset(&o, &a, &b);
    sigandset(&n, &a, &b);
    printf("orset=%d andset_empty=%d\n",
           sigismember(&o, SIGUSR1) && sigismember(&o, SIGUSR2), sigisemptyset(&n));

    printf("fpclassify: zero=%d normal=%d inf=%d nan=%d sub=%d\n",
           fpclassify(0.0) == FP_ZERO, fpclassify(1.0) == FP_NORMAL,
           fpclassify(INFINITY) == FP_INFINITE, fpclassify(NAN) == FP_NAN,
           fpclassify(DBL_MIN / 4) == FP_SUBNORMAL);
    return 0;
}
