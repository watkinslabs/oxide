// /bin/rpm — query subset of RPM CLI: -q / -qi / -qp.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdint.h>

#define BUF_CAP (4 * 1024 * 1024)

static long mmap_file(const char* path, long* out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    long size = (long)st.st_size;
    if (size <= 0 || size > BUF_CAP) { close(fd); return -1; }
    void* p = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return -1;
    *out_len = size;
    return (long)p;
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

static long parse_hdr(const uint8_t* buf, long cap, const uint8_t** idx_out,
                      const uint8_t** store_out, long* count_out) {
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

static long find_tag(const uint8_t* idx, long count, uint32_t tag,
                     uint32_t* type_out, uint32_t* nelem_out) {
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

static int find_pkg_header(const uint8_t* buf, long cap,
                           const uint8_t** idx_out, const uint8_t** store_out,
                           long* count_out) {
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
                           long store_cap, uint32_t tag) {
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

int main(int argc, char** argv, char** envp) {
    (void)envp;
    if (argc < 3) {
        write(2, "rpm: usage: rpm -q|-qi|-qp <file.rpm>\n", 38);
        return 2;
    }
    const char* op = argv[1];
    int info  = strcmp(op, "-qi") == 0;
    int query = strcmp(op, "-q") == 0 || strcmp(op, "-qp") == 0;
    if (!info && !query) {
        write(2, "rpm: only -q / -qi / -qp supported\n", 35);
        return 2;
    }
    const char* path = argv[2];
    long size = 0;
    long addr = mmap_file(path, &size);
    if (addr < 0) {
        write(2, "rpm: cannot read: ", 18);
        write(2, path, strlen(path));
        write(2, "\n", 1);
        return 1;
    }
    const uint8_t* buf = (const uint8_t*)addr;
    const uint8_t *idx, *store; long count;
    if (find_pkg_header(buf, size, &idx, &store, &count) != 0) {
        write(2, "rpm: malformed RPM\n", 19);
        return 1;
    }
    long store_cap = size - (store - buf);

    const char* name    = tag_str(idx, count, store, store_cap, RPMTAG_NAME);
    const char* version = tag_str(idx, count, store, store_cap, RPMTAG_VERSION);
    const char* release = tag_str(idx, count, store, store_cap, RPMTAG_RELEASE);
    const char* arch    = tag_str(idx, count, store, store_cap, RPMTAG_ARCH);
    const char* summary = tag_str(idx, count, store, store_cap, RPMTAG_SUMMARY);

    if (!name || !version || !release || !arch) {
        write(2, "rpm: missing core tags\n", 23);
        return 1;
    }

    if (query) {
        long o = 0;
        long n = strlen(name);    memcpy(out + o, name, n); o += n;    out[o++] = '-';
        n = strlen(version);      memcpy(out + o, version, n); o += n; out[o++] = '-';
        n = strlen(release);      memcpy(out + o, release, n); o += n; out[o++] = '.';
        n = strlen(arch);         memcpy(out + o, arch, n); o += n;
        out[o++] = '\n';
        write(1, out, o);
    } else {
        const char* prefixes[] = { "Name        : ", "Version     : ", "Release     : ", "Architecture: ", "Summary     : " };
        const char* values[]   = { name, version, release, arch, summary ? summary : "(none)" };
        for (int i = 0; i < 5; i++) {
            write(1, prefixes[i], strlen(prefixes[i]));
            write(1, values[i], strlen(values[i]));
            write(1, "\n", 1);
        }
    }
    return 0;
}
