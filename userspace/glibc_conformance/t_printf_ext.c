/* GNU printf extension registry basics: register_printf_type ID allocation. */
#define _GNU_SOURCE
#include <printf.h>
#include <stdarg.h>
#include <stdio.h>

static void read_arg(void *mem, va_list *ap) {
    (void)mem;
    (void)ap;
}

int main(void) {
    int a = register_printf_type(NULL);
    int b = register_printf_type(read_arg);
    int c = register_printf_type(read_arg);
    printf("types=%d,%d,%d\n", a, b, c);
    return 0;
}
