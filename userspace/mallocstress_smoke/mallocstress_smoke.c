// Exercises musl mallocng (malloc/free/realloc) the way CPython's
// allocator churn does — many live blocks of varied size classes,
// freed and reallocated in a pattern that forces mallocng group
// mmap/munmap/madvise + meta-area recycling. Pre-existing python
// `import`/alloc SIGSEGV is mallocng's a_crash() tripping on this
// churn; this probe reproduces it without CPython. Built BOTH static
// and dynamic (see rootfs.rs) so we can tell whether the trigger is
// mallocng-generic or specific to the dynamic-link memory layout.
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int w(const char*s){ return write(1,(s),strlen(s)); }

#define N 4096
static void *slots[N];
static size_t szs[N];

// size classes spanning mallocng's small/medium/large boundaries.
static const size_t classes[] = {
    16, 24, 40, 64, 100, 200, 360, 512, 1000, 2000, 4096, 9000,
    16384, 40000, 132096 /* >128K → individually mmapped */
};
#define NC (sizeof(classes)/sizeof(classes[0]))

int main(void){
    w("mallocstress: start\n");
    unsigned long rng = 0x12345678;
    for(int round=0; round<60; round++){
        for(int i=0;i<N;i++){
            rng = rng*1103515245 + 12345;
            int idx = (rng>>16) % N;
            if(slots[idx]){
                // verify our sentinel survived (detects aliasing/stale)
                unsigned char *p = slots[idx];
                if(p[0] != (unsigned char)(szs[idx]) ){
                    w("mallocstress: SENTINEL CORRUPT\n");
                    return 2;
                }
                free(slots[idx]);
                slots[idx]=0;
            }
            size_t s = classes[(rng>>8)%NC];
            void *p = malloc(s);
            if(!p){ w("mallocstress: OOM\n"); return 3; }
            memset(p, 0, s);
            ((unsigned char*)p)[0] = (unsigned char)s;   // sentinel
            slots[idx]=p; szs[idx]=s;
            // occasionally realloc to exercise that path
            if(((rng>>20)&7)==0){
                size_t ns = classes[(rng>>12)%NC];
                void *q = realloc(p, ns);
                if(q){ slots[idx]=q; szs[idx]=ns; ((unsigned char*)q)[0]=(unsigned char)ns; }
            }
        }
    }
    for(int i=0;i<N;i++) if(slots[i]) free(slots[i]);

    // High-watermark phase: mirror CPython `[bytearray(2000) for _ in
    // range(K)]` — many simultaneously-LIVE medium blocks, then free all.
    // This is what tripped python's free-path a_crash; few-live churn
    // above did not. Keep footprint modest vs 1G RAM but large enough to
    // force many mallocng groups + meta-area growth.
    w("mallocstress: hiwater start\n");
    enum { K = 120000 };
    static void *big[K];
    for(int i=0;i<K;i++){
        unsigned char *p = malloc(2000);
        if(!p){ w("mallocstress: hiwater OOM (ok-ish)\n");
                for(int j=0;j<i;j++) free(big[j]);
                w("mallocstress: ALL PASS\n"); return 0; }
        memset(p, 0x5A, 2000);          // touch every page
        big[i]=p;
    }
    // free in forward order (frees adjacent groups → exercises get_meta)
    for(int i=0;i<K;i++) free(big[i]);
    w("mallocstress: ALL PASS\n");
    return 0;
}
