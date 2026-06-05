// Regression test for B53: mremap(MAYMOVE) that relocates a mapping
// must tear down the SOURCE range's PTEs + frames, not just its VMA.
//
// Pre-fix oxide removed only the source VMA on a move, leaving the old
// VA's PTEs mapped to the old frames. The vacated VA then became an
// allocatable hole; a later mmap reusing it hit the stale PTE (no
// demand-fault) and silently read the OLD frame's contents instead of
// a fresh zero page — the mechanism behind musl mallocng's a_crash()
// during `python3 -c "import json"`.
//
// This probe forces that exact sequence and asserts the reused VA
// reads as zero (fresh), failing if stale bytes survive.
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>

#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif

static int w(const char*s){ return write(1,(s),strlen(s)); }
#define OLD (64*1024)
#define NEW (256*1024)
#define PG  4096

static int probe(void){
    // 1. Map a region and stamp every byte with a non-zero pattern.
    unsigned char *a = mmap(0, OLD, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(a==MAP_FAILED) return 10;
    memset(a, 0xAB, OLD);
    uintptr_t old_va = (uintptr_t)a;

    // 2. Grow via mremap(MAYMOVE) — forces a move to a new VA. The old
    //    VA [old_va, old_va+OLD) must be fully torn down.
    unsigned char *b = mremap(a, OLD, NEW, MREMAP_MAYMOVE);
    if(b==MAP_FAILED) return 11;
    uintptr_t new_va = (uintptr_t)b;
    if(new_va == old_va) return 0;        // grew in place (no move) — N/A

    // 3. Reclaim the vacated VA with fresh anonymous mappings and read
    //    BEFORE writing. A fresh anon page is guaranteed zero; a stale
    //    PTE left by the buggy move would expose the 0xAB pattern.
    for(int i=0;i<32;i++){
        unsigned char *c = mmap(0, OLD, PROT_READ|PROT_WRITE,
                                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if(c==MAP_FAILED) return 12;
        for(size_t o=0;o<OLD;o+=8){
            uint64_t v; memcpy(&v, c+o, 8);
            if(v != 0){
                w("mremap_alias: STALE PTE — reused VA not zero\n");
                return 1;
            }
        }
        // also verify the moved data survived intact at the new VA
        if(c == b){ /* shouldn't alias the live mapping */ }
        munmap(c, OLD);
    }
    // moved contents must be intact
    for(size_t o=0;o<OLD;o++) if(b[o]!=0xAB){ w("mremap_alias: moved data lost\n"); return 2; }
    munmap(b, NEW);
    return 0;
}

int main(void){
    w("mremap_alias: start\n");
    for(int r=0;r<8;r++){
        int rc=probe();
        if(rc){ w("mremap_alias: FAIL\n"); return rc; }
    }
    w("mremap_alias: ALL PASS\n");
    return 0;
}
