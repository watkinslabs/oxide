#include <stdio.h>
#include <wctype.h>
int main(void){
    printf("%d%d%d ", iswalpha(L'A')!=0, iswdigit(L'5')!=0, iswspace(L' ')!=0);
    printf("%d%d ", iswupper(L'X')!=0, iswlower(L'x')!=0);
    printf("up=%lc lo=%lc\n", towupper(L'a'), towlower(L'B'));
    return 0;
}
