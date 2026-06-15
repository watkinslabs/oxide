#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
int main(void){
    wchar_t w[16]; int n = mbstowcs(w, "hello", 16); printf("mbstowcs n=%d w0=%d\n", n, (int)w[0]);
    char b[16]; int m = wcstombs(b, w, 16); b[m]=0; printf("wcstombs m=%d s=%s\n", m, b);
    printf("wcslen=%zu\n", wcslen(L"abcd"));
    return 0;
}
