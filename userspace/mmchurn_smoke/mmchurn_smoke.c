// Isolates the mallocng-style mmap/munmap/madvise reuse pattern that
// trips musl's a_crash under python import. Verifies the kernel's
// zero/teardown guarantees that mallocng relies on.
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>

static int w(const char*s){ return write(1,s,strlen(s)); }
static void hx(uint64_t v){ char b[19]="0x"; for(int i=0;i<16;i++){int n=(v>>((15-i)*4))&0xf; b[2+i]=n<10?'0'+n:'a'+n-10;} b[18]=0; w(b); }

#define PG 4096

// Test 1: munmap then mmap-same-size, expect fresh zero. Loop.
static int t_remap(void){
    void *prev=0;
    for(int i=0;i<2000;i++){
        size_t len = ((i%5)+1)*PG;
        unsigned char *p = mmap(0,len,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(p==MAP_FAILED) return 10;
        // read-before-write: must be zero (fresh anon)
        for(size_t o=0;o<len;o+=8){ uint64_t v; memcpy(&v,p+o,8); if(v){ w("t_remap STALE @"); hx((uint64_t)(p+o)); w(" ="); hx(v); w(" i="); hx(i); w("\n"); return 1; } }
        // write a recognizable pattern
        memset(p,0xAB,len);
        munmap(p,len);
        prev=p; (void)prev;
    }
    return 0;
}

// Test 2: MADV_DONTNEED must zero on refault.
static int t_dontneed(void){
    size_t len=64*PG;
    unsigned char *p=mmap(0,len,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED) return 20;
    for(int i=0;i<500;i++){
        memset(p,0xCD,len);
        if(madvise(p,len,MADV_DONTNEED)!=0) return 21;
        for(size_t o=0;o<len;o+=8){ uint64_t v; memcpy(&v,p+o,8); if(v){ w("t_dontneed STALE @"); hx((uint64_t)(p+o)); w(" ="); hx(v); w(" i="); hx(i); w("\n"); return 2; } }
    }
    munmap(p,len);
    return 0;
}

// Test 3: MADV_FREE then WRITE then read = written value (no surprise zero/stale on write-after-free).
static int t_free(void){
    size_t len=64*PG;
    unsigned char *p=mmap(0,len,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED) return 30;
    for(int i=0;i<500;i++){
        memset(p,0x11,len);
        if(madvise(p,len,8 /*MADV_FREE*/)!=0) return 31;
        memset(p,0x22,len);                 // write-after-free: un-frees
        for(size_t o=0;o<len;o+=8){ uint64_t v; memcpy(&v,p+o,8); if(v!=0x2222222222222222ULL){ w("t_free WRONG @"); hx((uint64_t)(p+o)); w(" ="); hx(v); w(" i="); hx(i); w("\n"); return 3; } }
    }
    munmap(p,len);
    return 0;
}

// Test 4: interleave many small mmap/munmap to force address reuse with
// different sizes, read-before-write zero check.
static int t_interleave(void){
    unsigned char *keep[32]; size_t klen[32];
    for(int i=0;i<32;i++){ keep[i]=0; klen[i]=0; }
    for(int i=0;i<4000;i++){
        int s=i%32;
        if(keep[s]){ munmap(keep[s],klen[s]); keep[s]=0; }
        size_t len=((i*7%9)+1)*PG;
        unsigned char*p=mmap(0,len,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(p==MAP_FAILED) return 40;
        for(size_t o=0;o<len;o+=64){ uint64_t v; memcpy(&v,p+o,8); if(v){ w("t_interleave STALE @"); hx((uint64_t)(p+o)); w(" ="); hx(v); w(" i="); hx(i); w("\n"); return 4; } }
        memset(p,0x5A,len);
        keep[s]=p; klen[s]=len;
    }
    for(int i=0;i<32;i++) if(keep[i]) munmap(keep[i],klen[i]);
    return 0;
}

int main(void){
    int r;
    w("mmchurn: start\n");
    if((r=t_remap())){ w("FAIL t_remap\n"); return r; } w("t_remap OK\n");
    if((r=t_dontneed())){ w("FAIL t_dontneed\n"); return r; } w("t_dontneed OK\n");
    if((r=t_free())){ w("FAIL t_free\n"); return r; } w("t_free OK\n");
    if((r=t_interleave())){ w("FAIL t_interleave\n"); return r; } w("t_interleave OK\n");
    w("mmchurn: ALL PASS\n");
    return 0;
}
