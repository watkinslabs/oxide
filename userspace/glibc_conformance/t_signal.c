#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
static volatile sig_atomic_t got = 0;
static void handler(int s){ got = s; }
int main(void){
    signal(SIGUSR1, handler);
    raise(SIGUSR1);
    printf("got=%d\n", got);
    struct sigaction sa = {0}; sa.sa_handler = handler;
    sigaction(SIGUSR2, &sa, NULL);
    raise(SIGUSR2);
    printf("got2=%d\n", got);
    errno = 0;
    int sr = sigreturn(NULL);
    printf("sigreturn=%d errno=%d\n", sr, sr < 0 ? errno : 0);
    return 0;
}
