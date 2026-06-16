/* strerrorname_np/strerrordesc_np/sigabbrev_np/sigdescr_np vs host glibc.
 * Exhaustive over errno 0..140 and signal 0..40 (NULL printed as "(null)"). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <signal.h>

static const char *s(const char *p){ return p ? p : "(null)"; }

int main(void){
    for(int e=0;e<=140;e++){
        const char *n = strerrorname_np(e);
        const char *d = strerrordesc_np(e);
        if(n || d) printf("e=%d name=%s desc=%s\n", e, s(n), s(d));
    }
    for(int sig=0;sig<=40;sig++){
        const char *a = sigabbrev_np(sig);
        const char *d = sigdescr_np(sig);
        if(a || d) printf("sig=%d abbr=%s desc=%s\n", sig, s(a), s(d));
    }
    return 0;
}
