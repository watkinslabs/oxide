/* Exhaustive ctype audit vs host glibc (C locale): every classification +
   case-conversion function over EOF and all 256 byte values. */
#include <stdio.h>
#include <ctype.h>

int main(void){
    for (int c = -1; c < 256; c++){
        printf("%d:%d%d%d%d%d%d%d%d%d%d%d%d|%d,%d\n", c,
            !!isalpha(c), !!isdigit(c), !!isalnum(c), !!isspace(c),
            !!isupper(c), !!islower(c), !!ispunct(c), !!isgraph(c),
            !!isprint(c), !!iscntrl(c), !!isblank(c), !!isxdigit(c),
            toupper(c), tolower(c));
    }
    return 0;
}
