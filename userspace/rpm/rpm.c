// /bin/rpm — query subset of RPM CLI.
//
// Usage:
//   rpm -q <file.rpm>           print name-version-release.arch
//   rpm -qi <file.rpm>          print Name/Version/Release/Arch/Summary lines
//   rpm -qp <file.rpm>          alias for -q (RHEL convention: -qp = query package file)
//
// v1 reads the package metadata only — does not extract the
// payload. cpio + gzip extraction lives behind a future
// `rpm -e` / `rpm -i`. Mirrors the Rust `rpm` crate's tag walker.

#include <sys/syscall.h>
#include <stdint.h>

#define O_RDONLY 0
#define AT_FDCWD -100
#define BUF_CAP (4 * 1024 * 1024)  // 4 MB max RPM file

static long sc1(long n, long a) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a) : "rcx","r11","memory"); return r;
}
static long sc3(long n, long a, long b, long c) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx","r11","memory"); return r;
}
static long sc4(long n, long a, long b, long c, long d) {
    long r; register long r10 __asm__("r10") = d;
    __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx","r11","memory");
    return r;
}
static long sc6(long n, long a, long b, long c, long d, long e, long f) {
    long r;
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8")  = e;
    register long r9  __asm__("r9")  = f;
    __asm__ volatile ("syscall" : "=a"(r)
        : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
        : "rcx","r11","memory");
    return r;
}

static long mlen(const char* s) { long n = 0; while (s[n]) n++; return n; }
static int  streq(const char* a, const char* b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}
static void wstr(int fd, const char* s) { sc3(SYS_write, fd, (long)s, mlen(s)); }

#define MAP_PRIVATE 2
#define PROT_READ 1

static long mmap_file(const char* path, long* out_len) {
    long fd = sc4(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0);
    if (fd < 0) return fd;
    // fstat for size
    struct { uint64_t pad[18]; } st;
    long r = sc3(SYS_fstat, fd, (long)&st, 0);
    if (r < 0) { sc1(SYS_close, fd); return r; }
    // Offset 48 in struct stat is st_size on Linux x86_64.
    uint64_t* p = (uint64_t*)&st;
    long size = (long)p[6];
    if (size <= 0 || size > BUF_CAP) { sc1(SYS_close, fd); return -1; }
    long addr = sc6(SYS_mmap, 0, size, PROT_READ, MAP_PRIVATE, fd, 0);
    sc1(SYS_close, fd);
    if (addr < 0 && addr > -4096) return addr;
    *out_len = size;
    return addr;
}

static uint32_t rd_be32(const uint8_t* b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

#define RPMTAG_NAME    1000
#define RPMTAG_VERSION 1001
#define RPMTAG_RELEASE 1002
#define RPMTAG_SUMMARY 1004
#define RPMTAG_ARCH    1022

#define TYPE_STRING    6
#define TYPE_I18N      9

// Walk a header section starting at `buf`; returns index ptr,
// store ptr, count via out args. Returns total section length.
static long parse_hdr(const uint8_t* buf, long cap, const uint8_t** idx_out,
                      const uint8_t** store_out, long* count_out)
{
    if (cap < 16) return -1;
    if (buf[0] != 0x8e || buf[1] != 0xad || buf[2] != 0xe8) return -1;
    long count = (long)rd_be32(buf + 8);
    long store_n = (long)rd_be32(buf + 12);
    long idx_off = 16;
    long store_off = idx_off + count * 16;
    long total = store_off + store_n;
    if (total > cap) return -1;
    *idx_out = buf + idx_off;
    *store_out = buf + store_off;
    *count_out = count;
    return total;
}

// Find a tag in idx[]; returns store offset or -1.
static long find_tag(const uint8_t* idx, long count, uint32_t tag,
                     uint32_t* type_out, uint32_t* nelem_out)
{
    for (long i = 0; i < count; i++) {
        const uint8_t* e = idx + i * 16;
        if (rd_be32(e) == tag) {
            if (type_out)  *type_out = rd_be32(e + 4);
            if (nelem_out) *nelem_out = rd_be32(e + 12);
            return (long)rd_be32(e + 8);
        }
    }
    return -1;
}

// Read the package header out of `buf` (the RPM file). Stores
// pointers to its index + store sections via out args. Returns
// 0 on success, -1 on parse failure.
static int find_pkg_header(const uint8_t* buf, long cap,
                           const uint8_t** idx_out, const uint8_t** store_out,
                           long* count_out)
{
    if (cap < 96) return -1;
    if (buf[0] != 0xed || buf[1] != 0xab || buf[2] != 0xee || buf[3] != 0xdb) return -1;
    long off = 96;
    const uint8_t *si, *ss; long sn;
    long sig_total = parse_hdr(buf + off, cap - off, &si, &ss, &sn);
    if (sig_total < 0) return -1;
    off += sig_total;
    off = (off + 7) & ~7L;
    if (off >= cap) return -1;
    return parse_hdr(buf + off, cap - off, idx_out, store_out, count_out) > 0 ? 0 : -1;
}

static const char* tag_str(const uint8_t* idx, long count, const uint8_t* store,
                           long store_cap, uint32_t tag)
{
    uint32_t typ, n;
    long off = find_tag(idx, count, tag, &typ, &n);
    if (off < 0) return 0;
    if (typ != TYPE_STRING && typ != TYPE_I18N) return 0;
    if (off >= store_cap) return 0;
    const char* s = (const char*)(store + off);
    long i = off;
    while (i < store_cap && store[i] != 0) i++;
    if (i >= store_cap) return 0;
    return s;
}

static char out[1024];

static long itos(long n, char* dst, long cap) {
    long len = mlen((const char*)dst);
    while (*(dst + len) == 0) {} // suppress unused-len warning path
    return len;
}

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char** argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t"
                      : "=r"(argc), "=r"(argv));
    if (argc < 3) {
        wstr(2, "rpm: usage: rpm -q|-qi|-qp <file.rpm>\n");
        sc1(SYS_exit, 2);
    }
    const char* op = argv[1];
    int info = streq(op, "-qi");
    int query = streq(op, "-q") || streq(op, "-qp");
    if (!info && !query) {
        wstr(2, "rpm: only -q / -qi / -qp supported\n");
        sc1(SYS_exit, 2);
    }
    const char* path = argv[2];
    long size = 0;
    long addr = mmap_file(path, &size);
    if (addr < 0) {
        wstr(2, "rpm: cannot read: ");
        wstr(2, path); wstr(2, "\n");
        sc1(SYS_exit, 1);
    }
    const uint8_t* buf = (const uint8_t*)addr;
    const uint8_t *idx, *store; long count;
    if (find_pkg_header(buf, size, &idx, &store, &count) != 0) {
        wstr(2, "rpm: malformed RPM\n");
        sc1(SYS_exit, 1);
    }
    long store_cap = size - (store - buf);

    const char* name    = tag_str(idx, count, store, store_cap, RPMTAG_NAME);
    const char* version = tag_str(idx, count, store, store_cap, RPMTAG_VERSION);
    const char* release = tag_str(idx, count, store, store_cap, RPMTAG_RELEASE);
    const char* arch    = tag_str(idx, count, store, store_cap, RPMTAG_ARCH);
    const char* summary = tag_str(idx, count, store, store_cap, RPMTAG_SUMMARY);

    if (!name || !version || !release || !arch) {
        wstr(2, "rpm: missing core tags\n");
        sc1(SYS_exit, 1);
    }

    if (query) {
        long o = 0;
        long n = mlen(name);    for (long i = 0; i < n; i++) out[o++] = name[i];    out[o++] = '-';
        n = mlen(version);      for (long i = 0; i < n; i++) out[o++] = version[i]; out[o++] = '-';
        n = mlen(release);      for (long i = 0; i < n; i++) out[o++] = release[i]; out[o++] = '.';
        n = mlen(arch);         for (long i = 0; i < n; i++) out[o++] = arch[i];
        out[o++] = '\n';
        sc3(SYS_write, 1, (long)out, o);
    } else {
        // -qi: pretty fields.
        const char* prefixes[] = { "Name        : ", "Version     : ", "Release     : ", "Architecture: ", "Summary     : " };
        const char* values[]   = { name, version, release, arch, summary ? summary : "(none)" };
        for (int i = 0; i < 5; i++) {
            wstr(1, prefixes[i]);
            wstr(1, values[i]);
            wstr(1, "\n");
        }
    }
    (void)itos; // suppress unused-fn
    sc1(SYS_exit, 0);
    __builtin_unreachable();
}
