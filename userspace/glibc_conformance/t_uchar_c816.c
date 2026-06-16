/* mbrtoc16/c16rtomb/mbrtoc8/c8rtomb vs host glibc (C.UTF-8). Covers ASCII,
 * 2/3/4-byte UTF-8, astral surrogate-pair path, round-trips, unit buffering. */
#include <stdio.h>
#include <string.h>
#include <uchar.h>
#include <locale.h>
#include <sys/types.h>

static const char *samples[] = { "A", "\xc3\xa9", "\xe2\x82\xac", "\xf0\x9f\x98\x80" };

static void c16_decode(const char *s){
    mbstate_t st; memset(&st,0,sizeof st);
    size_t n = strlen(s), i = 0; int guard=0;
    printf("c16dec[%s]:", s);
    while(i < n && guard++ < 8){
        char16_t c; size_t r = mbrtoc16(&c, s+i, n-i, &st);
        if(r == (size_t)-3){ printf(" lo=%04x", c); continue; }
        if(r == (size_t)-1){ printf(" ERR"); break; }
        if(r == (size_t)-2){ printf(" INC"); break; }
        if(r == 0){ printf(" nul"); break; }
        printf(" u=%04x(r=%zu)", c, r); i += r;
    }
    printf("\n");
}
static void c16_roundtrip(const char *s){
    mbstate_t ds, es; memset(&ds,0,sizeof ds); memset(&es,0,sizeof es);
    size_t n = strlen(s), i = 0; char out[16]; size_t o=0; int guard=0;
    while(i < n && guard++ < 8){
        char16_t c; size_t r = mbrtoc16(&c, s+i, n-i, &ds);
        if(r == (size_t)-3){ o += c16rtomb(out+o, c, &es); continue; }
        if(r == 0 || r == (size_t)-1 || r == (size_t)-2) break;
        o += c16rtomb(out+o, c, &es); i += r;
    }
    out[o]=0;
    printf("c16rt[%s]: match=%d len=%zu\n", s, strcmp(out,s)==0, o);
}
static void c8_roundtrip(const char *s){
    mbstate_t ds, es; memset(&ds,0,sizeof ds); memset(&es,0,sizeof es);
    size_t n = strlen(s), i = 0; char out[16]; size_t o=0; int guard=0;
    printf("c8[%s]:", s);
    while(i < n && guard++ < 12){
        char8_t u; size_t r = mbrtoc8(&u, s+i, n-i, &ds);
        if(r == (size_t)-3){ printf(" %02x", u); o += c8rtomb(out+o,u,&es); continue; }
        if(r == (size_t)-1){ printf(" ERR"); break; }
        if(r == (size_t)-2){ printf(" INC"); break; }
        printf(" %02x(r=%zu)", u, r);
        o += c8rtomb(out+o, u, &es);
        if(r == 0) break;
        i += r;
    }
    out[o]=0;
    printf(" back=%d\n", strcmp(out,s)==0);
}
int main(void){
    setlocale(LC_ALL, "C.UTF-8");
    for(size_t k=0;k<4;k++) c16_decode(samples[k]);
    for(size_t k=0;k<4;k++) c16_roundtrip(samples[k]);
    for(size_t k=0;k<4;k++) c8_roundtrip(samples[k]);
    char b[8]; mbstate_t st; memset(&st,0,sizeof st);
    size_t r = c16rtomb(b, 0xDC00, &st);
    printf("lone-low: r=%zd\n", (ssize_t)r);
    return 0;
}
