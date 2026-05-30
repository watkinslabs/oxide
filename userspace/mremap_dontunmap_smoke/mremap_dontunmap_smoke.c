// /bin/mremap_dontunmap_smoke — verifies MREMAP_DONTUNMAP per
// Linux semantics (mremap(2), since 5.7).
//
// Contract:
//   * MREMAP_DONTUNMAP requires MREMAP_MAYMOVE.
//   * Anonymous + private mapping only.
//   * new_size == old_size (no resize).
//   * After the call the source VMA remains mapped but reads
//     refault as fresh zero pages; the destination holds the
//     original contents.

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#ifndef MREMAP_MAYMOVE
#  define MREMAP_MAYMOVE   1
#endif
#ifndef MREMAP_DONTUNMAP
#  define MREMAP_DONTUNMAP 4
#endif

#define PASS_MSG "mremap_dontunmap_smoke: PASS\n"
#define FAIL_MSG "mremap_dontunmap_smoke: FAIL\n"

static int fail(const char *why) {
    (void)why;
    write(1, FAIL_MSG, sizeof(FAIL_MSG) - 1);
    return 1;
}

int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv; (void)envp;

    void *src = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (src == MAP_FAILED) return fail("mmap");

    // Mark the page with a recognisable pattern.
    for (int i = 0; i < 4096; i++) ((volatile unsigned char*)src)[i] = 0xAB;

    void *dst = mremap(src, 4096, 4096,
                       MREMAP_MAYMOVE | MREMAP_DONTUNMAP);
    if (dst == MAP_FAILED) return fail("mremap");

    // Destination must hold the original 0xAB bytes.
    for (int i = 0; i < 4096; i++) {
        if (((volatile unsigned char*)dst)[i] != 0xAB) return fail("dst");
    }

    // Source must still be mapped, but reads refault as zero.
    for (int i = 0; i < 4096; i++) {
        if (((volatile unsigned char*)src)[i] != 0x00) return fail("src");
    }

    write(1, PASS_MSG, sizeof(PASS_MSG) - 1);
    return 0;
}
