#include <stdio.h>
#include <stdlib.h>
static void a(void){ printf("atexit-a\n"); }
static void b(void){ printf("atexit-b\n"); }
int main(void){ atexit(a); atexit(b); printf("main-end\n"); return 0; }
