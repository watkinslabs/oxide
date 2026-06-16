/* C-runtime aux: MB_CUR_MAX per locale, SIGRTMIN/MAX, CPU_COUNT, eventfd
 * read/write helpers, __cxa_finalize no-op. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <signal.h>
#include <sched.h>
#include <sys/eventfd.h>

int main(void) {
    setlocale(LC_ALL, "C");
    printf("mb_c=%d\n", (int)MB_CUR_MAX);
    setlocale(LC_ALL, "C.UTF-8");
    printf("mb_utf8=%d\n", (int)MB_CUR_MAX);

    printf("rtmin_ge=%d rtmax=%d\n", SIGRTMIN >= 32, SIGRTMAX);

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); CPU_SET(3,&cs); CPU_SET(7,&cs);
    printf("cpucount=%d\n", CPU_COUNT(&cs));

    int ef = eventfd(0,0); eventfd_t v=0;
    eventfd_write(ef, 9);
    eventfd_read(ef, &v);
    printf("eventfd=%llu\n", (unsigned long long)v);
    return 0;
}
