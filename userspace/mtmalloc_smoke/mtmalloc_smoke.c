// Concurrent malloc/free churn across pthreads — tests whether musl
// mallocng's internal lock actually serializes under oxide's
// preemption/futex on SMP=1. If the lock doesn't block, two threads
// mutate mallocng metadata concurrently → corruption → a_crash().
// (CPython holds the GIL but still runs OS threads; this isolates the
// kernel lock/futex behaviour from CPython.)
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>

static int w(const char*s){ return write(1,(s),strlen(s)); }

#define NT 4
#define PER 1500

static volatile int corrupt = 0;

static void *worker(void *arg){
    unsigned long rng = 0xabcdef ^ (unsigned long)(uintptr_t)arg;
    void *slots[64]; size_t szs[64];
    for(int i=0;i<64;i++){ slots[i]=0; szs[i]=0; }
    for(int r=0;r<PER;r++){
        for(int i=0;i<64;i++){
            rng = rng*1103515245 + 12345;
            int idx=(rng>>16)&63;
            if(slots[idx]){
                unsigned char *p=slots[idx];
                if(p[0]!=(unsigned char)szs[idx]){ corrupt=1; return 0; }
                free(slots[idx]); slots[idx]=0;
            }
            size_t s = 16 + ((rng>>8)%4096);
            unsigned char *p=malloc(s);
            if(!p) return 0;
            memset(p,0,s); p[0]=(unsigned char)s;
            slots[idx]=p; szs[idx]=s;
        }
    }
    for(int i=0;i<64;i++) if(slots[i]) free(slots[i]);
    return 0;
}

int main(void){
    w("mtmalloc: start\n");
    pthread_t t[NT];
    for(int i=0;i<NT;i++) if(pthread_create(&t[i],0,worker,(void*)(uintptr_t)(i+1))){ w("mtmalloc: pthread_create FAIL\n"); return 5; }
    for(int i=0;i<NT;i++) pthread_join(t[i],0);
    if(corrupt){ w("mtmalloc: SENTINEL CORRUPT\n"); return 2; }
    w("mtmalloc: ALL PASS\n");
    return 0;
}
