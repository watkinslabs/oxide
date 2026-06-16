/* inet_net_pton/ntop/neta/nsap_addr/nsap_ntoa vs host glibc (libresolv). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
static void np(const char*s){
    unsigned char b[8]; memset(b,0,8); errno=0;
    int r = inet_net_pton(AF_INET, s, b, sizeof b);
    printf("pton(%-16s)=%2d %02x.%02x.%02x.%02x e=%d\n", s, r, b[0],b[1],b[2],b[3], r<0?errno:0);
}
static void nt(unsigned a,unsigned bb,unsigned c,unsigned d,int bits){
    unsigned char raw[4]={a,bb,c,d}; char out[64];
    char *r = inet_net_ntop(AF_INET, raw, bits, out, sizeof out);
    printf("ntop(%u.%u.%u.%u/%d)=%s\n", a,bb,c,d,bits, r?r:"(null)");
}
static void neta(unsigned n){ char b[64]; char*r=inet_neta(n,b,sizeof b); printf("neta(0x%08x)=%s\n", n, r?r:"(null)"); }
int main(void){
    const char *ps[]={"192.168.1.0","192.168.1","192.168","10","192.168.1.0/24",
        "10/8","0x0a000001","1.2.3.4/32","128.0.0.0/1","172.16/12","0xc0a8",
        "255.255.255.255","0xdeadbeef","224.0.0.1","240.1"};
    for(int i=0;i<15;i++) np(ps[i]);
    nt(192,168,1,0,24); nt(10,0,0,0,8); nt(192,168,1,0,32); nt(10,0,0,0,9);
    nt(128,0,0,0,1); nt(172,16,0,0,12); nt(0,0,0,0,0); nt(255,255,255,255,32);
    unsigned netas[]={0x0a000001,0xc0a80100,0x0a000000,0,0xff000000,0x01020304,
        0x000000ff,0x0a0b0000,0x00ff00ff};
    for(int i=0;i<9;i++) neta(netas[i]);
    unsigned char buf[32]; memset(buf,0,32);
    unsigned r = inet_nsap_addr("47.0005.80.005a00.0000.0001.e133.ffffff000162.00", buf, sizeof buf);
    printf("nsap_addr=%u:", r); for(unsigned i=0;i<r;i++) printf("%02x", buf[i]); printf("\n");
    unsigned char bin[]={0x47,0x00,0x05,0x80}; char asc[80];
    printf("nsap_ntoa=%s\n", inet_nsap_ntoa(4, bin, asc));
    unsigned char bin2[]={0xde,0xad,0xbe,0xef,0x01};
    printf("nsap_ntoa2=%s\n", inet_nsap_ntoa(5, bin2, asc));
    return 0;
}
