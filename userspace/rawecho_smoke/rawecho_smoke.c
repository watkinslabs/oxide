// Isolates the "raw-mode userspace self-echo" path that bash/readline
// uses at an interactive prompt: put the tty in raw mode (ICANON+ECHO
// off), then read each byte and write it straight back to stdout. If
// this fails to echo on the console while kernel canonical echo (cat)
// works, the defect is in the userspace tty write/raw path, not klog.
//
// Reads up to `N` bytes (or until newline) so a scripted driver can
// inject a fixed string and observe the echo. Prints a framed result.
#include <unistd.h>
#include <termios.h>
#include <string.h>

static int w(const char*s){ return write(1,(s),strlen(s)); }

int main(void){
    w("rawecho: start (type; echoes each byte)\n");
    struct termios old, raw;
    if(tcgetattr(0,&old)!=0){ w("rawecho: tcgetattr FAIL\n"); return 2; }
    raw = old;
    raw.c_lflag &= ~(ICANON | ECHO | ISIG | IEXTEN);
    raw.c_iflag &= ~(ICRNL | IXON);
    raw.c_cc[VMIN]=1; raw.c_cc[VTIME]=0;
    if(tcsetattr(0,TCSANOW,&raw)!=0){ w("rawecho: tcsetattr FAIL\n"); return 3; }

    int n=0;
    char c;
    while(n < 64){
        ssize_t r = read(0,&c,1);
        if(r<=0) break;
        n++;
        // echo the byte back, exactly like readline redisplay does.
        if(c=='\r'||c=='\n'){ w("\r\n"); break; }
        write(1,&c,1);
    }
    tcsetattr(0,TCSANOW,&old);
    w("\nrawecho: done\n");
    return 0;
}
