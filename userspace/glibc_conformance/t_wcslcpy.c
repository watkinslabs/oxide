/* wcslcpy/wcslcat vs host glibc — BSD bounded wide-string copy/concat. */
#include <stdio.h>
#include <wchar.h>
int main(void){
    wchar_t buf[16];
    /* wcslcpy: truncation, exact-fit, size 0, oversized */
    size_t sizes[] = {0,1,4,6,16};
    for(int i=0;i<5;i++){
        for(size_t k=0;k<16;k++) buf[k]=L'#';
        size_t r = wcslcpy(buf, L"hello", sizes[i]);
        printf("lcpy(size=%zu) r=%zu buf=", sizes[i], r);
        if(sizes[i]>0) printf("[%ls]\n", buf); else printf("[untouched]\n");
    }
    /* wcslcat: append within bounds */
    struct { const wchar_t *init; const wchar_t *add; size_t sz; } cases[] = {
        {L"ab", L"cdef", 16}, {L"ab", L"cdef", 5}, {L"ab", L"cdef", 3},
        {L"ab", L"cdef", 2}, {L"", L"xyz", 4}, {L"full", L"x", 4},
    };
    for(int i=0;i<6;i++){
        for(size_t k=0;k<16;k++) buf[k]=0;
        wcscpy(buf, cases[i].init);
        size_t r = wcslcat(buf, cases[i].add, cases[i].sz);
        printf("lcat(\"%ls\"+\"%ls\",sz=%zu) r=%zu buf=[%ls]\n",
               cases[i].init, cases[i].add, cases[i].sz, r, buf);
    }
    return 0;
}
