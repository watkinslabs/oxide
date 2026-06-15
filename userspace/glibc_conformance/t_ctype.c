#include <stdio.h>
#include <ctype.h>
int main(void){
    for(int c='A'; c<='G'; c++) printf("%c:%d%d%d ", c, isalpha(c)!=0, isdigit(c)!=0, isupper(c)!=0);
    printf("\n");
    printf("tolower=%c toupper=%c\n", tolower('X'), toupper('x'));
    printf("space=%d punct=%d alnum=%d\n", isspace(' ')!=0, ispunct('!')!=0, isalnum('7')!=0);
    return 0;
}
