// malloc/free churn while a high-frequency timer signal fires. Tests
// whether oxide's signal delivery preserves the interrupted user
// context across a malloc critical section. If signal frame
// setup/sigreturn clobbers a register or user memory mid-malloc, the
// in-progress mallocng metadata update corrupts → a_crash() later.
// (CPython installs signal handlers + uses interpreter timers, so its
// malloc runs are constantly interruptible; this isolates that.)
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <stdint.h>

static int w(const char*s){ return write(1,(s),strlen(s)); }
static volatile sig_atomic_t ticks = 0;
static volatile void *scratch;

static void on_alrm(int sig){
    (void)sig;
    ticks++;
    // Touch the heap from signal context the way a deferred handler's
    // bookkeeping might; small alloc to stress reentrancy of the frame
    // setup (NOT mallocng reentrancy — freed immediately).
    void *p = malloc(32);
    if(p){ memset(p,0x77,32); scratch=p; free(p); }
}

int main(void){
    w("sigmalloc: start\n");
    struct sigaction sa; memset(&sa,0,sizeof sa);
    sa.sa_handler = on_alrm;
    sigaction(SIGALRM, &sa, 0);
    struct itimerval it;
    it.it_interval.tv_sec=0; it.it_interval.tv_usec=500;   // 0.5ms
    it.it_value = it.it_interval;
    setitimer(ITIMER_REAL, &it, 0);

    void *slots[256]; size_t szs[256];
    for(int i=0;i<256;i++){ slots[i]=0; szs[i]=0; }
    unsigned long rng=0x5eed;
    for(int r=0;r<40000;r++){
        rng=rng*1103515245+12345;
        int idx=(rng>>16)&255;
        if(slots[idx]){
            unsigned char*p=slots[idx];
            if(p[0]!=(unsigned char)szs[idx] || p[szs[idx]-1]!=(unsigned char)(szs[idx]>>1)){
                w("sigmalloc: SENTINEL CORRUPT\n"); return 2;
            }
            free(slots[idx]); slots[idx]=0;
        }
        size_t s=16+((rng>>8)%8000);
        unsigned char*p=malloc(s);
        if(!p){ w("sigmalloc: OOM\n"); return 3; }
        memset(p,0,s);
        p[0]=(unsigned char)s; p[s-1]=(unsigned char)(s>>1);
        slots[idx]=p; szs[idx]=s;
    }
    for(int i=0;i<256;i++) if(slots[i]) free(slots[i]);
    it.it_value.tv_sec=0; it.it_value.tv_usec=0; setitimer(ITIMER_REAL,&it,0);
    if(ticks==0) w("sigmalloc: WARN no ticks fired\n");
    w("sigmalloc: ALL PASS\n");
    return 0;
}
