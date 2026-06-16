/* inet6_opt_* (RFC3542 HBH/Dest options) vs host glibc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
static void dump(unsigned char*b,int n){ printf("buf:"); for(int i=0;i<n;i++) printf(" %02x", b[i]); printf("\n"); }
int main(void){
    /* length pass */
    int a=inet6_opt_init(NULL,0);
    int b=inet6_opt_append(NULL,0,a,0x07,4,4,NULL);
    int c=inet6_opt_append(NULL,0,b,0x08,2,2,NULL);
    int d=inet6_opt_append(NULL,0,c,0x05,1,1,NULL);
    int e=inet6_opt_append(NULL,0,d,0x06,4,4,NULL); /* forces a pad */
    int t=inet6_opt_finish(NULL,0,e);
    printf("len: a=%d b=%d c=%d d=%d e=%d t=%d\n", a,b,c,d,e,t);
    printf("badalign=%d\n", inet6_opt_append(NULL,0,2,9,4,8,NULL)); /* align8>len4 -> -1 */

    unsigned char buf[64]; memset(buf,0xee,sizeof buf);
    int l=inet6_opt_init(buf,t);
    void*d1; int o=inet6_opt_append(buf,t,l,0x07,4,4,&d1);
    unsigned int v1=0x11223344; inet6_opt_set_val(d1,0,&v1,4);
    void*d2; o=inet6_opt_append(buf,t,o,0x08,2,2,&d2);
    unsigned short v2=0x5566; inet6_opt_set_val(d2,0,&v2,2);
    void*d3; o=inet6_opt_append(buf,t,o,0x05,1,1,&d3);
    unsigned char v3=0xaa; inet6_opt_set_val(d3,0,&v3,1);
    void*d4; o=inet6_opt_append(buf,t,o,0x06,4,4,&d4);
    unsigned int v4=0xdeadbeef; inet6_opt_set_val(d4,0,&v4,4);
    o=inet6_opt_finish(buf,t,o);
    printf("build o=%d hdrlen=%u\n", o, buf[1]);
    dump(buf,t);

    /* iterate */
    int pos=0; uint8_t ty; socklen_t ln; void*dp;
    while((pos=inet6_opt_next(buf,t,pos,&ty,&ln,&dp))!=-1)
        printf("next type=%u len=%u off=%ld\n", ty, (unsigned)ln, (unsigned char*)dp-buf);
    /* find type 6, read its value */
    socklen_t fl; void*fd;
    int fp=inet6_opt_find(buf,t,0,0x06,&fl,&fd);
    unsigned int got=0; if(fp!=-1) inet6_opt_get_val(fd,0,&got,4);
    printf("find6 fp=%d len=%u val=%08x\n", fp, (unsigned)fl, got);
    printf("find_missing=%d\n", inet6_opt_find(buf,t,0,0x99,&fl,&fd));
    return 0;
}
