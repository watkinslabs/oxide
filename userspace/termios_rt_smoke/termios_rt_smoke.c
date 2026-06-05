// Verifies tcgetattr/tcsetattr round-trip for the bits readline relies
// on (ICANON, ECHO). readline saves the termios, clears ICANON|ECHO,
// and decides whether to self-echo from what it reads back. If oxide's
// TCSETS doesn't persist a cleared ECHO bit that a later TCGETS sees,
// readline's echo logic breaks → no incremental echo at the bash
// prompt (BUG A) even though kernel canonical echo works.
#include <unistd.h>
#include <termios.h>
#include <string.h>

static int w(const char*s){ return write(1,(s),strlen(s)); }
static void hx(unsigned long v){ char b[19]="0x"; for(int i=0;i<16;i++){int n=(v>>((15-i)*4))&0xf; b[2+i]=n<10?'0'+n:'a'+n-10;} b[18]=0; w(b); }

int main(void){
    w("termios_rt: start\n");
    struct termios t0;
    if(tcgetattr(0,&t0)!=0){ w("termios_rt: tcgetattr0 FAIL\n"); return 2; }
    w("termios_rt: initial c_lflag="); hx(t0.c_lflag); w("\n");

    struct termios t1 = t0;
    t1.c_lflag &= ~((unsigned)(ICANON | ECHO));
    if(tcsetattr(0,TCSANOW,&t1)!=0){ w("termios_rt: tcsetattr FAIL\n"); return 3; }

    struct termios t2;
    if(tcgetattr(0,&t2)!=0){ w("termios_rt: tcgetattr2 FAIL\n"); return 4; }
    w("termios_rt: after-clear c_lflag="); hx(t2.c_lflag); w("\n");

    int ok = ((t2.c_lflag & (ICANON|ECHO)) == 0);
    // restore
    tcsetattr(0,TCSANOW,&t0);
    if(!ok){ w("termios_rt: MISMATCH — cleared bits did not persist\n"); return 1; }
    w("termios_rt: ROUNDTRIP OK\n");
    return 0;
}
