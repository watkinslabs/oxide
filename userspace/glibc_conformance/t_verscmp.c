#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
static int s(int x){ return x<0?-1:x>0?1:0; }
int main(void){
    const char *pairs[][2] = {
        {"000","00"}, {"alpha1","alpha001"}, {"part1_1","part1_10"},
        {"item-1.0.0","item-1.0.1"}, {"foo","foo"}, {"1","10"},
        {"jan1","jan10"}, {"5.9","5.10"}, {"01","010"}, {"x009y","x09y"},
        {"file9","file10"}, {"a","a1"},
    };
    for (int i=0;i<12;i++)
        printf("%s<>%s=%d\n", pairs[i][0], pairs[i][1], s(strverscmp(pairs[i][0], pairs[i][1])));
    return 0;
}
