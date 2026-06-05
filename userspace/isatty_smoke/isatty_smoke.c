// BUG A triage: readline echoes via fwrite() to the stdout FILE* and
// relies on it being line-buffered/unbuffered (musl picks that from
// isatty(1) at first use). If isatty(1) is wrong, stdout is fully
// buffered and per-char echo accumulates until newline → no
// incremental echo at the bash prompt while kernel echo works.
#include <unistd.h>
#include <stdio.h>
#include <string.h>

static int w(const char*s){ return write(1,(s),strlen(s)); }

int main(void){
    char b[64];
    int a0=isatty(0), a1=isatty(1), a2=isatty(2);
    snprintf(b,sizeof b,"isatty: 0=%d 1=%d 2=%d\n",a0,a1,a2);
    w(b);
    // stdio buffering probe: write WITHOUT newline via stdio, then a
    // marker via raw write. On a tty stdout musl is line-buffered, so
    // "NOFLUSH" stays buffered until the explicit fflush below.
    fputs("NOFLUSH_PART", stdout);     // no newline
    w("|RAW_AFTER_FPUTS|");            // raw write jumps ahead of buffered text
    fflush(stdout);
    w("\nisatty_smoke: done\n");
    return 0;
}
