/* rtld dlopen target (docs/59§5): a tiny self-contained shared lib exporting
 * one function. Built -shared -nostdlib (no DT_NEEDED). */
int foo(void) { return 99; }
