/* getifaddrs/freeifaddrs vs host glibc. Same machine -> same kernel netlink
 * dump -> same interface/address set. Order between the two libcs may differ,
 * so we format each entry into a line and sort before printing. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>

static int cmp(const void *a, const void *b){
    return strcmp(*(const char *const*)a, *(const char *const*)b);
}

static void fmt_sa(char *out, size_t n, const struct sockaddr *sa){
    if(!sa){ snprintf(out,n,"-"); return; }
    if(sa->sa_family==AF_INET){
        char b[64]; const struct sockaddr_in *s=(const void*)sa;
        inet_ntop(AF_INET,&s->sin_addr,b,sizeof b); snprintf(out,n,"%s",b);
    } else if(sa->sa_family==AF_INET6){
        char b[64]; const struct sockaddr_in6 *s=(const void*)sa;
        inet_ntop(AF_INET6,&s->sin6_addr,b,sizeof b); snprintf(out,n,"%s",b);
    } else if(sa->sa_family==AF_PACKET){
        const struct sockaddr_ll *s=(const void*)sa; char b[64]; int o=0;
        for(int i=0;i<s->sll_halen && o<60;i++) o+=snprintf(b+o,sizeof b-o,"%02x",s->sll_addr[i]);
        if(s->sll_halen==0) snprintf(b,sizeof b,"none");
        snprintf(out,n,"ll:%s",b);
    } else snprintf(out,n,"af%d",sa->sa_family);
}

int main(void){
    struct ifaddrs *ifa, *p;
    if(getifaddrs(&ifa)!=0){ perror("getifaddrs"); return 1; }
    char *lines[256]; int nl=0;
    for(p=ifa; p && nl<256; p=p->ifa_next){
        int fam = p->ifa_addr ? p->ifa_addr->sa_family : -1;
        char a[80], m[80], br[80];
        fmt_sa(a,sizeof a,p->ifa_addr);
        fmt_sa(m,sizeof m,p->ifa_netmask);
        fmt_sa(br,sizeof br,p->ifa_broadaddr);
        char *ln = malloc(256);
        snprintf(ln,256,"%-8s fam=%2d addr=%s mask=%s bcast=%s",
                 p->ifa_name?p->ifa_name:"?", fam, a, m, br);
        lines[nl++]=ln;
    }
    freeifaddrs(ifa);
    qsort(lines,nl,sizeof lines[0],cmp);
    for(int i=0;i<nl;i++){ puts(lines[i]); free(lines[i]); }
    printf("count=%d\n", nl);
    return 0;
}
