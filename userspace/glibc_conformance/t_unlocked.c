/* stdio _unlocked variants + flockfile vs host glibc (over a memory stream). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(void){
    char buf[64] = "abcdef\nghij";
    FILE *r = fmemopen(buf, strlen(buf), "r");
    flockfile(r);
    printf("getc=%c fgetc=%c\n", getc_unlocked(r), fgetc_unlocked(r));
    char line[16]; fgets_unlocked(line, sizeof line, r);
    printf("fgets=%s eof=%d err=%d\n", line, feof_unlocked(r), ferror_unlocked(r));
    char chunk[8]; size_t n = fread_unlocked(chunk, 1, 4, r); chunk[n]=0;
    printf("fread=%zu %s fileno=%d\n", n, chunk, fileno_unlocked(r));
    clearerr_unlocked(r);
    funlockfile(r);
    fclose(r);

    /* write side to a dynamic memstream */
    char *mp; size_t ms;
    FILE *w = open_memstream(&mp, &ms);
    fputs_unlocked("hello ", w);
    fputc_unlocked('X', w);
    fwrite_unlocked("YZ", 1, 2, w);
    fflush_unlocked(w);
    printf("written=%s size=%zu trylock=%d\n", mp, ms, ftrylockfile(w));
    fclose(w);
    free(mp);
    return 0;
}
