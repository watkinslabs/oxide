// /lib/ld-musl-x86_64.so.1 — real dynamic linker for oxide v2 phase 33.
//
// Replaces the P13-06 stub with a working DT_NEEDED resolver. Loads
// each named shared object from /lib/ → /lib64/ → /usr/lib/, mmaps
// its PT_LOAD segments, recurses into its DT_NEEDED transitively,
// builds a symbol-resolution chain (BFS), applies R_X86_64_RELATIVE /
// _GLOB_DAT / _JUMP_SLOT / _64 relocations on every loaded DSO + the
// exec, runs DT_INIT_ARRAY for each library, then jumps to the exec.
//
// Intentional v2 phase 33 first-cut omissions:
//   * Lazy binding (PLT entries are eager-resolved here).
//   * IFUNC (R_X86_64_IRELATIVE).
//   * TLS init image (DT_TLSDESC, DTV setup) — single-thread programs.
//   * dlopen / dlsym (no runtime loader API).
//   * GNU symbol versioning (DT_VERNEED / DT_VERSYM).
//   * R_X86_64_COPY (limited use cases).
// Modern musl-built binaries that don't use TLS / IFUNC / versioning
// link cleanly. glibc-built binaries need the deferred items.

#include <stdint.h>
#include <stddef.h>

// ---- syscall numbers (Linux x86_64) ----
#define SYS_read   0
#define SYS_write  1
#define SYS_open   2
#define SYS_close  3
#define SYS_mmap   9
#define SYS_exit   60
#define SYS_lseek  8

#define O_RDONLY   0
#define MAP_PRIVATE 0x02
#define PROT_READ   1
#define PROT_WRITE  2
#define PROT_EXEC   4

// ---- inline syscalls ----

static inline long sc1(long n, long a) {
    long r;
    __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a) : "rcx","r11","memory");
    return r;
}
static inline long sc2(long n, long a, long b) {
    long r;
    __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b) : "rcx","r11","memory");
    return r;
}
static inline long sc3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx","r11","memory");
    return r;
}
static inline long sc6(long n, long a, long b, long c, long d, long e, long f) {
    long r;
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8")  = e;
    register long r9  __asm__("r9")  = f;
    __asm__ volatile ("syscall" : "=a"(r)
        : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
        : "rcx","r11","memory");
    return r;
}

// ---- minimal libc ----

static long mlen(const char* s) { long n=0; while (s[n]) n++; return n; }
static int  meq(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}
static void mcp(void* d, const void* s, long n) {
    char* dd = (char*)d; const char* ss = (const char*)s;
    for (long i = 0; i < n; i++) dd[i] = ss[i];
}
static void mst(void* d, int b, long n) {
    char* dd = (char*)d;
    for (long i = 0; i < n; i++) dd[i] = (char)b;
}

static void writes(const char* s) { sc3(SYS_write, 2, (long)s, mlen(s)); }
static void hex16(unsigned long v, char* out) {
    static const char digits[] = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) { out[i] = digits[v & 0xf]; v >>= 4; }
    out[16] = 0;
}
static void writex(unsigned long v) {
    char b[17]; hex16(v, b);
    sc3(SYS_write, 2, (long)"0x", 2);
    sc3(SYS_write, 2, (long)b, 16);
}
static void die(const char* msg) {
    writes("dl: fatal: "); writes(msg); writes("\n");
    sc1(SYS_exit, 127);
    __builtin_unreachable();
}

// ---- ELF64 ----

typedef struct { uint8_t e_ident[16]; uint16_t e_type, e_machine; uint32_t e_version;
                 uint64_t e_entry, e_phoff, e_shoff; uint32_t e_flags;
                 uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx; } Ehdr;
typedef struct { uint32_t p_type, p_flags; uint64_t p_offset, p_vaddr, p_paddr,
                 p_filesz, p_memsz, p_align; } Phdr;
typedef struct { int64_t d_tag; uint64_t d_un; } Dyn;
typedef struct { uint32_t st_name; uint8_t st_info, st_other; uint16_t st_shndx;
                 uint64_t st_value, st_size; } Sym;
typedef struct { uint64_t r_offset; uint64_t r_info; int64_t r_addend; } Rela;

#define PT_LOAD     1
#define PT_DYNAMIC  2
#define PT_INTERP   3
#define PT_PHDR     6

#define DT_NULL      0
#define DT_NEEDED    1
#define DT_PLTRELSZ  2
#define DT_PLTGOT    3
#define DT_HASH      4
#define DT_STRTAB    5
#define DT_SYMTAB    6
#define DT_RELA      7
#define DT_RELASZ    8
#define DT_RELAENT   9
#define DT_STRSZ     10
#define DT_SYMENT    11
#define DT_INIT      12
#define DT_FINI      13
#define DT_SONAME    14
#define DT_PLTREL    20
#define DT_JMPREL    23
#define DT_INIT_ARRAY    25
#define DT_INIT_ARRAYSZ  27
#define DT_GNU_HASH  0x6ffffef5

#define R_X86_64_NONE      0
#define R_X86_64_64        1
#define R_X86_64_GLOB_DAT  6
#define R_X86_64_JUMP_SLOT 7
#define R_X86_64_RELATIVE  8

#define ELF64_R_SYM(i)  ((i) >> 32)
#define ELF64_R_TYPE(i) ((i) & 0xffffffff)
#define ELF64_ST_BIND(info) ((info) >> 4)
#define STB_WEAK 2

#define MAX_DSOS 32
#define PAGE     4096

typedef struct dso {
    uint64_t  base;          // load bias for this DSO (0 for non-PIE exec)
    uint64_t  entry;         // exec only; 0 for libraries
    Dyn*      dynamic;       // PT_DYNAMIC, biased
    const char* strtab;
    Sym*      symtab;
    uint32_t* hash;          // legacy SysV hash (DT_HASH)
    uint32_t* gnu_hash;      // DT_GNU_HASH
    Rela*     rela;
    long      relasz;
    Rela*     pltrel;        // DT_JMPREL (only RELA in v1)
    long      pltrelsz;
    void    (**init_array)(void);
    long      init_array_n;
    char      name[64];
    int       relocated;
} Dso;

static Dso     dsos[MAX_DSOS];
static int     n_dsos = 0;

// ---- read full file at path into a kernel-allocated buffer ----

static long open_path(const char* path) {
    return sc3(SYS_open, (long)path, O_RDONLY, 0);
}

static long read_full(int fd, void* buf, long want) {
    long got = 0;
    while (got < want) {
        long n = sc3(SYS_read, fd, (long)((char*)buf + got), want - got);
        if (n <= 0) return n < 0 ? n : got;
        got += n;
    }
    return got;
}

static long pread_at(int fd, void* buf, long want, long off) {
    if (sc3(SYS_lseek, fd, off, 0) < 0) return -1;
    return read_full(fd, buf, want);
}

// ---- locate SO file: try /lib/<name>, /lib64/<name>, /usr/lib/<name> ----

static int try_open(const char* dir, const char* name, char* fullbuf, long fullbuf_sz) {
    long dl = mlen(dir), nl = mlen(name);
    if (dl + 1 + nl + 1 > fullbuf_sz) return -1;
    mcp(fullbuf, dir, dl);
    fullbuf[dl] = '/';
    mcp(fullbuf + dl + 1, name, nl + 1);
    long fd = open_path(fullbuf);
    return (int)fd;
}

static int locate_so(const char* name, char* path_out, long path_out_sz) {
    static const char* dirs[] = { "/lib", "/lib64", "/usr/lib", "/usr/lib64", 0 };
    for (int i = 0; dirs[i]; i++) {
        int fd = try_open(dirs[i], name, path_out, path_out_sz);
        if (fd >= 0) return fd;
    }
    return -1;
}

// ---- mmap a PT_LOAD into place at base+vaddr, size = memsz ----

static long page_down(long v) { return v & ~(long)(PAGE - 1); }
static long page_up(long v)   { return (v + PAGE - 1) & ~(long)(PAGE - 1); }

static int load_phdrs_at_base(int fd, Ehdr* eh, Phdr* phs, uint64_t base) {
    for (int i = 0; i < eh->e_phnum; i++) {
        Phdr* p = &phs[i];
        if (p->p_type != PT_LOAD) continue;
        uint64_t va_start = base + page_down((long)p->p_vaddr);
        uint64_t va_end   = base + page_up((long)(p->p_vaddr + p->p_memsz));
        long len = (long)(va_end - va_start);
        int prot = PROT_READ | PROT_WRITE; // load-time relocations need W; reprotect later
        if (p->p_flags & 1) prot |= PROT_EXEC;
        long ret = sc6(SYS_mmap, (long)va_start, len, prot,
                       MAP_PRIVATE | 0x10 /*MAP_FIXED*/ | 0x20 /*MAP_ANONYMOUS*/,
                       -1, 0);
        if (ret < 0 || (uint64_t)ret != va_start) return -1;
        // Read file content into the mapping at the in-page offset.
        long file_off  = (long)p->p_offset;
        long file_size = (long)p->p_filesz;
        long va_off    = (long)p->p_vaddr - page_down((long)p->p_vaddr);
        if (file_size > 0) {
            if (pread_at(fd, (void*)(va_start + va_off), file_size, file_off) < file_size)
                return -1;
        }
        // BSS tail (memsz > filesz) is zero from MAP_ANONYMOUS.
    }
    return 0;
}

// ---- parse PT_DYNAMIC into dso fields ----

static void parse_dynamic(Dso* d) {
    for (Dyn* dy = d->dynamic; dy && dy->d_tag != DT_NULL; dy++) {
        uint64_t v = dy->d_un;
        switch (dy->d_tag) {
            case DT_STRTAB:    d->strtab    = (const char*)(d->base + v); break;
            case DT_SYMTAB:    d->symtab    = (Sym*)(d->base + v); break;
            case DT_HASH:      d->hash      = (uint32_t*)(d->base + v); break;
            case DT_GNU_HASH:  d->gnu_hash  = (uint32_t*)(d->base + v); break;
            case DT_RELA:      d->rela      = (Rela*)(d->base + v); break;
            case DT_RELASZ:    d->relasz    = (long)v; break;
            case DT_JMPREL:    d->pltrel    = (Rela*)(d->base + v); break;
            case DT_PLTRELSZ:  d->pltrelsz  = (long)v; break;
            case DT_INIT_ARRAY:    d->init_array   = (void(**)(void))(d->base + v); break;
            case DT_INIT_ARRAYSZ:  d->init_array_n = (long)(v / 8); break;
            default: break;
        }
    }
}

// ---- DT_HASH (SysV) lookup ----

static uint32_t sysv_hash(const char* s) {
    uint32_t h = 0, g;
    while (*s) {
        h = (h << 4) + (uint8_t)*s++;
        g = h & 0xf0000000;
        if (g) h ^= g >> 24;
        h &= 0x0fffffff;
    }
    return h;
}

static Sym* lookup_in_dso(Dso* d, const char* name) {
    if (!d->symtab || !d->strtab || !d->hash) return 0;
    uint32_t nbucket = d->hash[0];
    uint32_t* bucket = d->hash + 2;
    uint32_t* chain  = bucket + nbucket;
    uint32_t h = sysv_hash(name);
    for (uint32_t y = bucket[h % nbucket]; y; y = chain[y]) {
        Sym* s = &d->symtab[y];
        const char* sn = d->strtab + s->st_name;
        if (s->st_value && meq(sn, name)) return s;
    }
    return 0;
}

// ---- load + recurse on DT_NEEDED ----

static int already_loaded(const char* name) {
    for (int i = 0; i < n_dsos; i++) {
        if (meq(dsos[i].name, name)) return 1;
    }
    return 0;
}

static int load_so_recursive(const char* name);

static int load_so(const char* name) {
    if (n_dsos >= MAX_DSOS) die("too many DSOs");
    if (already_loaded(name)) return 0;

    char pathbuf[256];
    int fd = locate_so(name, pathbuf, sizeof pathbuf);
    if (fd < 0) {
        writes("dl: not found: "); writes(name); writes("\n");
        return -1;
    }

    Ehdr eh;
    if (read_full(fd, &eh, sizeof eh) != sizeof eh) { sc1(SYS_close, fd); return -1; }
    if (eh.e_ident[0] != 0x7f || eh.e_ident[1] != 'E') { sc1(SYS_close, fd); return -1; }

    Phdr phs[24];
    if (eh.e_phnum > 24) { sc1(SYS_close, fd); return -1; }
    if (pread_at(fd, phs, sizeof(Phdr) * eh.e_phnum, (long)eh.e_phoff)
        != (long)(sizeof(Phdr) * eh.e_phnum)) { sc1(SYS_close, fd); return -1; }

    // Compute load span — picking a non-overlapping bias from the
    // kernel's mmap. We ask for a fresh anonymous range covering the
    // SO's PT_LOAD span, then load PT_LOADs into it.
    uint64_t lo = ~(uint64_t)0, hi = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        Phdr* p = &phs[i];
        if (p->p_type != PT_LOAD) continue;
        if (p->p_vaddr < lo) lo = p->p_vaddr;
        if (p->p_vaddr + p->p_memsz > hi) hi = p->p_vaddr + p->p_memsz;
    }
    long span = (long)(page_up((long)hi) - page_down((long)lo));
    long reserve = sc6(SYS_mmap, 0, span, PROT_READ,
                       MAP_PRIVATE | 0x20 /*ANON*/, -1, 0);
    if (reserve < 0) { sc1(SYS_close, fd); return -1; }
    uint64_t base = (uint64_t)reserve - page_down((long)lo);

    if (load_phdrs_at_base(fd, &eh, phs, base) < 0) { sc1(SYS_close, fd); return -1; }

    Dso* d = &dsos[n_dsos++];
    mst(d, 0, sizeof *d);
    d->base = base;
    long nlen = mlen(name);
    if (nlen >= (long)sizeof d->name) nlen = sizeof d->name - 1;
    mcp(d->name, name, nlen); d->name[nlen] = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (phs[i].p_type == PT_DYNAMIC) {
            d->dynamic = (Dyn*)(base + phs[i].p_vaddr);
        }
    }
    parse_dynamic(d);
    sc1(SYS_close, fd);

    // Recurse into this DSO's DT_NEEDED entries.
    for (Dyn* dy = d->dynamic; dy && dy->d_tag != DT_NULL; dy++) {
        if (dy->d_tag == DT_NEEDED) {
            const char* nm = d->strtab + dy->d_un;
            load_so_recursive(nm);
        }
    }
    return 0;
}

static int load_so_recursive(const char* name) { return load_so(name); }

// ---- symbol resolution across the loaded DSO chain ----

static uint64_t resolve_global(const char* name, int allow_weak_zero) {
    for (int i = 0; i < n_dsos; i++) {
        Sym* s = lookup_in_dso(&dsos[i], name);
        if (s) return dsos[i].base + s->st_value;
    }
    if (allow_weak_zero) return 0;
    writes("dl: unresolved: "); writes(name); writes("\n");
    return 0;
}

// ---- apply RELA + JMPREL to one DSO ----

static void apply_relas(Dso* d, Rela* tab, long size_bytes) {
    if (!tab || size_bytes <= 0) return;
    long n = size_bytes / (long)sizeof(Rela);
    for (long i = 0; i < n; i++) {
        Rela* r = &tab[i];
        uint64_t* slot = (uint64_t*)(d->base + r->r_offset);
        uint64_t  type = ELF64_R_TYPE(r->r_info);
        uint64_t  symi = ELF64_R_SYM(r->r_info);
        switch (type) {
            case R_X86_64_RELATIVE:
                *slot = d->base + (uint64_t)r->r_addend;
                break;
            case R_X86_64_64: {
                Sym* s = &d->symtab[symi];
                const char* nm = d->strtab + s->st_name;
                uint64_t v;
                if (s->st_value && symi != 0) {
                    v = d->base + s->st_value + (uint64_t)r->r_addend;
                } else {
                    v = resolve_global(nm, ELF64_ST_BIND(s->st_info) == STB_WEAK)
                        + (uint64_t)r->r_addend;
                }
                *slot = v;
                break;
            }
            case R_X86_64_GLOB_DAT:
            case R_X86_64_JUMP_SLOT: {
                Sym* s = &d->symtab[symi];
                const char* nm = d->strtab + s->st_name;
                uint64_t v;
                if (s->st_value && symi != 0) {
                    v = d->base + s->st_value;
                } else {
                    v = resolve_global(nm, ELF64_ST_BIND(s->st_info) == STB_WEAK);
                }
                *slot = v;
                break;
            }
            case R_X86_64_NONE: break;
            default:
                writes("dl: unsupported reloc type "); writex(type); writes("\n");
                break;
        }
    }
}

static void relocate_dso(Dso* d) {
    if (d->relocated) return;
    d->relocated = 1;
    apply_relas(d, d->rela, d->relasz);
    apply_relas(d, d->pltrel, d->pltrelsz);
}

static void run_init_arrays(void) {
    // Run library init arrays in load order (after the exec, before
    // returning to the exec's _start).
    for (int i = 1; i < n_dsos; i++) {
        Dso* d = &dsos[i];
        for (long j = 0; j < d->init_array_n; j++) {
            if (d->init_array[j]) d->init_array[j]();
        }
    }
}

// ---- discover the exec from the auxv ----

#define AT_NULL    0
#define AT_PHDR    3
#define AT_PHENT   4
#define AT_PHNUM   5
#define AT_BASE    7
#define AT_ENTRY   9

long dl_main(long* sp) {
    long argc = sp[0];
    long* p = sp + 1 + argc + 1;
    while (*p) p++;
    p++;

    uint64_t exec_phdr  = 0;
    uint64_t exec_phnum = 0;
    uint64_t exec_phent = 0;
    uint64_t exec_entry = 0;
    uint64_t our_base   = 0;
    while (*p != AT_NULL) {
        long tag = p[0]; long val = p[1];
        switch (tag) {
            case AT_PHDR:  exec_phdr  = (uint64_t)val; break;
            case AT_PHENT: exec_phent = (uint64_t)val; break;
            case AT_PHNUM: exec_phnum = (uint64_t)val; break;
            case AT_BASE:  our_base   = (uint64_t)val; break;
            case AT_ENTRY: exec_entry = (uint64_t)val; break;
        }
        p += 2;
    }
    (void)our_base;

    // Walk the exec's program headers (mapped already by the kernel).
    // Find PT_DYNAMIC + the load bias (PT_PHDR points at the live phdr
    // table; subtracting its file offset from its current VA gives the
    // exec's load bias).
    Phdr* phs = (Phdr*)exec_phdr;
    if (!phs || !exec_phnum) die("no exec phdrs in auxv");
    if (exec_phent != sizeof(Phdr)) die("phent size mismatch");

    uint64_t exec_base    = 0;
    Dyn*     exec_dynamic = 0;
    uint64_t exec_phdr_va = 0;
    uint64_t exec_phdr_off = 0;
    for (uint64_t i = 0; i < exec_phnum; i++) {
        Phdr* ph = &phs[i];
        if (ph->p_type == PT_PHDR) {
            exec_phdr_va  = ph->p_vaddr;
            exec_phdr_off = ph->p_offset;
        }
    }
    // Bias: addr_of_phdr_in_memory - addr_of_phdr_in_file.
    if (exec_phdr_va) {
        // The kernel handed us AT_PHDR = exec_base + exec_phdr_va.
        exec_base = (uint64_t)exec_phdr - exec_phdr_va;
    }
    // Compute the actual entry point (load bias + e_entry from auxv path).
    // We don't have e_entry on its own; AT_ENTRY already includes the bias.
    // Re-find DYNAMIC from the bias-adjusted phdrs.
    for (uint64_t i = 0; i < exec_phnum; i++) {
        Phdr* ph = &phs[i];
        if (ph->p_type == PT_DYNAMIC) {
            exec_dynamic = (Dyn*)(exec_base + ph->p_vaddr);
        }
    }

    // Slot 0 = exec.
    Dso* exec_dso = &dsos[n_dsos++];
    mst(exec_dso, 0, sizeof *exec_dso);
    exec_dso->base    = exec_base;
    exec_dso->entry   = exec_entry;
    exec_dso->dynamic = exec_dynamic;
    mcp(exec_dso->name, "[exec]", 7);
    parse_dynamic(exec_dso);

    // Walk the exec's DT_NEEDED.
    if (exec_dynamic) {
        for (Dyn* dy = exec_dynamic; dy && dy->d_tag != DT_NULL; dy++) {
            if (dy->d_tag == DT_NEEDED) {
                const char* nm = exec_dso->strtab + dy->d_un;
                load_so(nm);
            }
        }
    }

    // Apply relocations to every DSO (libraries first, then exec).
    for (int i = n_dsos - 1; i >= 1; i--) relocate_dso(&dsos[i]);
    relocate_dso(exec_dso);

    // Run library init arrays.
    run_init_arrays();

    if (!exec_entry) die("AT_ENTRY missing");
    return (long)exec_entry;
}

__attribute__((naked, noreturn))
void _start(void) {
    __asm__ volatile (
        "mov  %%rsp, %%rbx\n\t"
        "mov  %%rsp, %%rdi\n\t"
        "and  $-16, %%rsp\n\t"
        "sub  $8,   %%rsp\n\t"
        "call dl_main\n\t"
        "mov  %%rbx, %%rsp\n\t"
        "jmp  *%%rax\n\t"
        : : : "rbx","memory"
    );
}
