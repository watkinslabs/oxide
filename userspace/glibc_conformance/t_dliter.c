/* dl_iterate_phdr: the callback must see the main executable's PT_LOAD covering
 * &main. vs host glibc (the boolean is identical even though object lists differ). */
#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>
#include <stdint.h>

static int found = 0;
static int cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    uintptr_t target = (uintptr_t)data;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        if (p->p_type == PT_LOAD) {
            uintptr_t lo = info->dlpi_addr + p->p_vaddr;
            uintptr_t hi = lo + p->p_memsz;
            if (target >= lo && target < hi) { found = 1; return 1; }
        }
    }
    return 0;
}

int main(void) {
    int r = dl_iterate_phdr(cb, (void *)(uintptr_t)&main);
    printf("ret=%d main_in_phdr=%d\n", r, found);
    return 0;
}
