#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(void){
    /* fmemopen read */
    char src[] = "line1\nline2\nrest";
    FILE *r = fmemopen(src, strlen(src), "r");
    char ln[32];
    fgets(ln, sizeof ln, r); printf("read1=%s", ln);
    int c = fgetc(r); printf("c=%c tell=%ld\n", c, ftell(r));
    fseek(r, 0, SEEK_SET);
    char all[64]; size_t got = fread(all, 1, sizeof all, r); all[got]=0;
    printf("reread_n=%zu\n", got);
    fclose(r);

    /* fmemopen write (fixed buffer, truncation) */
    char wbuf[8];
    FILE *w = fmemopen(wbuf, sizeof wbuf, "w");
    int n = fprintf(w, "abcdefghij"); /* 10 chars into 8-byte buf */
    fflush(w);
    printf("wrote_ret=%d buf=%s tell=%ld\n", n, wbuf, ftell(w));
    fclose(w);

    /* open_memstream: dynamic growth via fprintf */
    char *mp; size_t ms;
    FILE *m = open_memstream(&mp, &ms);
    for (int i=0;i<5;i++) fprintf(m, "[%d]", i);
    fputc('!', m);
    fflush(m);
    printf("memstream=%s size=%zu\n", mp, ms);
    fclose(m);
    free(mp);
    return 0;
}
