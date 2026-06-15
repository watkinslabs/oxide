/* inet_aton/addr/ntoa/makeaddr/lnaof/netof vs host glibc. */
#include <stdio.h>
#include <arpa/inet.h>
int main(void){
    const char *good[] = {"192.168.1.1","10.0.0.255","0.0.0.0","255.255.255.255",
                          "127.0.0.1","1.2.3.4","16909060","0x7f.0.0.1","010.020.030.040"};
    for (size_t i=0;i<sizeof good/sizeof good[0];i++){
        struct in_addr a;
        int r = inet_aton(good[i], &a);
        printf("aton(%s)=%d ntoa=%s addr=%08x\n", good[i], r, r?inet_ntoa(a):"-", r?a.s_addr:0);
    }
    const char *bad[] = {"256.1.1.1","1.2.3.4.5","abc","","1..2"};
    for (size_t i=0;i<5;i++){ struct in_addr a; printf("bad(%s)=%d addr=%08x\n", bad[i], inet_aton(bad[i],&a), inet_addr(bad[i])); }

    struct in_addr m = inet_makeaddr(0xc0a801, 5);  /* class C net */
    printf("makeaddr=%s lnaof=%x netof=%x\n", inet_ntoa(m), inet_lnaof(m), inet_netof(m));
    struct in_addr m2 = inet_makeaddr(10, 0x010203);
    printf("makeA=%s lnaof=%x netof=%x\n", inet_ntoa(m2), inet_lnaof(m2), inet_netof(m2));
    printf("network=%08x\n", inet_network("192.168.0.0"));
    return 0;
}
