/* GNU async getaddrinfo status helpers: completed/unsubmitted requests. */
#define _GNU_SOURCE
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static void pr(const char *name, int r) {
    printf("%s=%d", name, r);
    if (r < 0) printf(" [%s]", gai_strerror(r));
    printf(" errno=%d\n", errno);
}

int main(void) {
    struct gaicb req;
    memset(&req, 0, sizeof req);
    const struct gaicb *list1[1] = { &req };
    const struct gaicb *listn[1] = { 0 };
    struct timespec z = { 0, 0 };

    errno = 0; pr("error_zero", gai_error(&req));
    errno = 0; pr("cancel_null", gai_cancel(NULL));
    errno = 0; pr("cancel_zero", gai_cancel(&req));
    errno = 0; pr("suspend_empty", gai_suspend(NULL, 0, &z));
    errno = 0; pr("suspend_zero", gai_suspend(list1, 1, &z));
    errno = 0; pr("suspend_null_req", gai_suspend(listn, 1, &z));
    printf("str_inprogress=%s\n", gai_strerror(EAI_INPROGRESS));
    printf("str_overflow=%s\n", gai_strerror(EAI_OVERFLOW));
    return 0;
}
