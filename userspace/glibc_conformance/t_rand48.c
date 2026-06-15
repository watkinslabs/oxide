/* rand48 + random PRNG families vs host glibc (exact algorithm match). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

int main(void){
    /* drand48 family seeded by srand48 */
    srand48(0x1234abcd);
    for (int i=0;i<5;i++) printf("lrand48=%ld\n", lrand48());
    for (int i=0;i<5;i++) printf("drand48=%.17g\n", drand48());
    for (int i=0;i<5;i++) printf("mrand48=%ld\n", mrand48());

    /* seed48 returns prior state; then jrand48 */
    unsigned short s[3] = {0x330e, 0xabcd, 0x1234};
    unsigned short *old = seed48(s);
    printf("seed48 old=%04x%04x%04x\n", old[0], old[1], old[2]);
    for (int i=0;i<4;i++) printf("jrand48=%ld\n", jrand48(s));

    /* erand48/nrand48 over explicit xsubi */
    unsigned short x[3] = {0x0001, 0x0002, 0x0003};
    for (int i=0;i<4;i++) printf("erand48=%.17g\n", erand48(x));
    unsigned short y[3] = {0xdead, 0xbeef, 0x0042};
    for (int i=0;i<4;i++) printf("nrand48=%ld\n", nrand48(y));

    /* lcong48 then drand48 */
    unsigned short p[7] = {1,2,3,4,5,6,7};
    lcong48(p);
    for (int i=0;i<3;i++) printf("lcong48 drand48=%.17g\n", drand48());

    /* random/srandom sequence */
    srandom(987654321u);
    for (int i=0;i<8;i++) printf("random=%ld\n", random());

    /* initstate/setstate */
    char st1[128];
    char st2[128];
    char *prev = initstate(13579u, st1, sizeof st1);
    (void)prev;
    for (int i=0;i<4;i++) printf("is1=%ld\n", random());
    initstate(24680u, st2, sizeof st2);
    for (int i=0;i<4;i++) printf("is2=%ld\n", random());
    setstate(st1);
    for (int i=0;i<4;i++) printf("ss1=%ld\n", random());

    /* reentrant random_r */
    struct random_data rd;
    char rbuf[128];
    int32_t rv;
    rd.state = NULL;
    initstate_r(424242u, rbuf, sizeof rbuf, &rd);
    for (int i=0;i<5;i++){ random_r(&rd, &rv); printf("random_r=%d\n", (int)rv); }

    /* reentrant drand48_r */
    struct drand48_data dd;
    double dv;
    long lv;
    srand48_r(0x55aa, &dd);
    for (int i=0;i<3;i++){ drand48_r(&dd, &dv); printf("drand48_r=%.17g\n", dv); }
    for (int i=0;i<3;i++){ lrand48_r(&dd, &lv); printf("lrand48_r=%ld\n", lv); }
    return 0;
}
