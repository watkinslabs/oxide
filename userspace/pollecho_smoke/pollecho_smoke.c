// Like rawecho_smoke but waits via poll(POLLIN) before reading — the
// path bash/readline uses (_rl_input_available / select). If poll on
// the console never reports POLLIN for raw-mode input that IS sitting
// in the kernel RX ring (blocking read() drains it fine), readline
// blocks and never echoes incrementally → BUG A. Reports per-char.
#define _GNU_SOURCE
#include <unistd.h>
#include <termios.h>
#include <poll.h>
#include <string.h>
#include <stdio.h>

static int w(const char*s){ return write(1,(s),strlen(s)); }

int main(void){
    w("pollecho: start\n");
    struct termios old, raw;
    if(tcgetattr(0,&old)!=0){ w("pollecho: tcgetattr FAIL\n"); return 2; }
    raw = old;
    raw.c_lflag &= ~(ICANON | ECHO | ISIG);
    raw.c_iflag &= ~(ICRNL);
    raw.c_cc[VMIN]=1; raw.c_cc[VTIME]=0;
    tcsetattr(0,TCSANOW,&raw);

    int n=0, polls=0, hits=0;
    while(n<32){
        struct pollfd pf = { .fd=0, .events=POLLIN, .revents=0 };
        int r = poll(&pf, 1, 1000);     // 1s timeout
        polls++;
        if(r<=0){ if(polls>40) break; continue; }   // timeout / no input
        if(pf.revents & POLLIN){
            hits++;
            char c; ssize_t k = read(0,&c,1);
            if(k<=0) break;
            n++;
            if(c=='\r'||c=='\n'){ w("\r\n"); break; }
            write(1,&c,1);              // incremental echo via poll path
        }
    }
    tcsetattr(0,TCSANOW,&old);
    char b[64]; snprintf(b,sizeof b,"\npollecho: done polls=%d pollin_hits=%d echoed=%d\n",polls,hits,n);
    w(b);
    // PASS only if poll actually reported readable for the typed input.
    w(hits>0 ? "pollecho: POLL_OK\n" : "pollecho: POLL_BROKEN\n");
    return hits>0 ? 0 : 1;
}
