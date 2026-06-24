/* ns_sprintrr/ns_sprintrrf DNS RR presentation formatting vs host glibc. */
#define _GNU_SOURCE
#include <arpa/nameser.h>
#include <stdio.h>
#include <string.h>

static void put16(unsigned char *p, unsigned v){ p[0]=v>>8; p[1]=v; }
static void put32(unsigned char *p, unsigned long v){ p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }
static int name(unsigned char *p, const char *s){
    unsigned char *b=p;
    const char *seg=s;
    while(*seg){
        const char *dot=strchr(seg,'.');
        int n=dot ? (int)(dot-seg) : (int)strlen(seg);
        *p++=n; memcpy(p,seg,n); p+=n;
        if(!dot) break;
        seg=dot+1;
    }
    *p++=0;
    return (int)(p-b);
}
static int rr(unsigned char *p, const char *owner, unsigned type, unsigned cls,
              unsigned ttl, const unsigned char *rdata, unsigned rdlen){
    unsigned char *b=p;
    p+=name(p,owner); put16(p,type); p+=2; put16(p,cls); p+=2;
    put32(p,ttl); p+=4; put16(p,rdlen); p+=2;
    memcpy(p,rdata,rdlen); p+=rdlen;
    return (int)(p-b);
}

static void run(const char *label, unsigned type, const unsigned char *rdata, unsigned rdlen){
    unsigned char m[512]; memset(m,0,sizeof m);
    unsigned char *p=m;
    put16(p,0x1234); p+=2; put16(p,0x8180); p+=2;
    put16(p,1); p+=2; put16(p,1); p+=2; put16(p,0); p+=2; put16(p,0); p+=2;
    p+=name(p,"www.example.com"); put16(p,1); p+=2; put16(p,1); p+=2;
    p+=rr(p,"www.example.com",type,1,3600,rdata,rdlen);
    ns_msg h; ns_rr a; char out[512];
    int r=ns_initparse(m,(int)(p-m),&h);
    int pa=ns_parserr(&h,ns_s_an,0,&a);
    int s=ns_sprintrr(&h,&a,NULL,NULL,out,sizeof out);
    printf("[%s] parse=%d/%d spr=%d <%s>\n", label, r, pa, s, s>=0?out:"");
    s=ns_sprintrr(&h,&a,NULL,"example.com.",out,sizeof out);
    printf("[%s] origin=%d <%s>\n", label, s, s>=0?out:"");
    if(type==ns_t_a || type==ns_t_aaaa || type==ns_t_txt || type==99){
        s=ns_sprintrrf(m,(size_t)(p-m),"www.example.com.",ns_c_in,(ns_type)type,3600,rdata,rdlen,NULL,NULL,out,sizeof out);
        printf("[%s] rf=%d <%s>\n", label, s, s>=0?out:"");
    }
}

int main(void){
    unsigned char a[4]={1,2,3,4};
    unsigned char aaaa[16]={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    unsigned char nbuf[80], cname[80], ptr[80], mx[96], txt[8]={5,'h','e','l','l','o'}, raw[3]={1,2,3};
    int n=name(nbuf,"ns.example.com"); run("A",ns_t_a,a,4);
    run("AAAA",ns_t_aaaa,aaaa,16);
    run("NS",ns_t_ns,nbuf,n);
    n=name(cname,"alias.example.com"); run("CNAME",ns_t_cname,cname,n);
    n=name(ptr,"ptr.example.com"); run("PTR",ns_t_ptr,ptr,n);
    put16(mx,10); n=name(mx+2,"mail.example.com"); run("MX",ns_t_mx,mx,n+2);
    run("TXT",ns_t_txt,txt,6);
    run("RAW99",99,raw,3);
    return 0;
}
