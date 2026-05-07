// /bin/passwd — change a user's password.
// Drepper sha512crypt; rewrites /etc/shadow atomically via shadow.new.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>

static int memeq(const char* a, const char* b, long n) {
    for (long i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static int read_line(int fd, char* dst, long cap) {
    long n = 0;
    while (n < cap - 1) {
        char c; ssize_t r = read(fd, &c, 1);
        if (r <= 0) break;
        if (c == '\n') break;
        dst[n++] = c;
    }
    dst[n] = 0; return (int)n;
}

#include "../shared/sha512crypt.h"

static int find_line(const char* text, long total, const char* name,
                     long* start_out, long* len_out) {
    long nl = strlen(name);
    long i = 0;
    while (i < total) {
        long s = i;
        while (i < total && text[i] != '\n') i++;
        long lnlen = i - s;
        if (lnlen > nl + 1 && text[s + nl] == ':' && memeq(text + s, name, nl)) {
            *start_out = s;
            *len_out = (i < total ? i + 1 : i) - s;
            return 1;
        }
        if (i < total && text[i] == '\n') i++;
    }
    return 0;
}

static int split_colons(char* line, char** f, int max) {
    int n = 0; f[n++] = line;
    for (long i = 0; line[i]; i++) {
        if (line[i] == ':') { line[i] = 0; if (n < max) f[n++] = &line[i+1]; }
    }
    return n;
}

static int verify_old(const char* password, const char* hash) {
    if (hash[0] == 0) return 1;
    if (hash[0] == '!' || hash[0] == '*') return 0;
    if (hash[0] != '$' || hash[1] != '6' || hash[2] != '$') return 0;
    char buf[160];
    long n = strlen(hash);
    if (n >= (long)sizeof(buf)) return 0;
    memcpy(buf, hash, n);
    buf[n] = 0;
    long i = 3;
    while (buf[i] && buf[i] != '$') i++;
    if (!buf[i]) return 0;
    buf[i] = 0;
    char* salt = &buf[3];
    char* expected = &buf[i+1];
    char computed[128];
    long got = sha512crypt(password, salt, 5000, computed);
    computed[got] = 0;
    return strcmp(computed, expected) == 0;
}

static void make_salt(char* out, long n) {
    uint8_t raw[16];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, raw, 16);
        close(fd);
    } else {
        struct timespec ts = {0, 0};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t x = (uint64_t)ts.tv_nsec ^ ((uint64_t)ts.tv_sec << 32);
        for (int i = 0; i < 16; i++) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            raw[i] = (uint8_t)x;
        }
    }
    for (long i = 0; i < n; i++) out[i] = SC_ALPH[raw[i] & 63];
    out[n] = 0;
}

static char passwd_buf[8192];
static char shadow_buf[16384];
static char old_input[128], new_input[128], conf_input[128];
static char salt_buf[16], hash_out[128];
static char new_shadow_buf[24576];

int main(int argc, char** argv, char** envp) {
    (void)envp;
    long uid = (long)getuid();
    char self_name[64] = "?";

    int pfd = open("/etc/passwd", O_RDONLY);
    if (pfd < 0) { write(2, "passwd: cannot open /etc/passwd\n", 32); return 1; }
    long pn = 0;
    while (pn < (long)sizeof(passwd_buf) - 1) {
        ssize_t r = read(pfd, passwd_buf + pn, sizeof(passwd_buf) - 1 - pn);
        if (r <= 0) break; pn += r;
    }
    close(pfd);
    passwd_buf[pn] = 0;

    {
        long i = 0;
        while (i < pn) {
            long s = i;
            while (i < pn && passwd_buf[i] != '\n') i++;
            long lnlen = i - s;
            if (lnlen > 0) {
                int colons = 0; long k = 0;
                while (k < lnlen && colons < 2) {
                    if (passwd_buf[s + k] == ':') colons++;
                    k++;
                }
                if (colons == 2) {
                    unsigned long u = 0; long m = k;
                    while (m < lnlen && passwd_buf[s + m] != ':') {
                        if (passwd_buf[s + m] >= '0' && passwd_buf[s + m] <= '9')
                            u = u * 10 + (passwd_buf[s + m] - '0');
                        else { u = ~0UL; break; }
                        m++;
                    }
                    if (u == (unsigned long)uid) {
                        long nl = 0;
                        while (nl < lnlen && passwd_buf[s + nl] != ':' && nl < (long)sizeof(self_name) - 1) {
                            self_name[nl] = passwd_buf[s + nl]; nl++;
                        }
                        self_name[nl] = 0;
                        break;
                    }
                }
            }
            if (i < pn) i++;
        }
    }

    const char* target = (argc >= 2 && argv[1] && argv[1][0]) ? argv[1] : self_name;
    if (uid != 0 && strcmp(target, self_name) != 0) {
        write(2, "passwd: only root may change another user\n", 42);
        return 1;
    }

    int sfd = open("/etc/shadow", O_RDONLY);
    if (sfd < 0) { write(2, "passwd: cannot open /etc/shadow\n", 32); return 1; }
    long sn = 0;
    while (sn < (long)sizeof(shadow_buf) - 1) {
        ssize_t r = read(sfd, shadow_buf + sn, sizeof(shadow_buf) - 1 - sn);
        if (r <= 0) break; sn += r;
    }
    close(sfd);
    shadow_buf[sn] = 0;

    long ls, ll;
    if (!find_line(shadow_buf, sn, target, &ls, &ll)) {
        write(2, "passwd: no shadow entry for user\n", 33); return 1;
    }

    char line_buf[1024];
    long copy_len = ll;
    if (copy_len > 0 && shadow_buf[ls + copy_len - 1] == '\n') copy_len--;
    if (copy_len >= (long)sizeof(line_buf)) { write(2, "passwd: line too long\n", 22); return 1; }
    memcpy(line_buf, shadow_buf + ls, copy_len);
    line_buf[copy_len] = 0;
    char* sf[12];
    int nf = split_colons(line_buf, sf, 12);
    if (nf < 9) { write(2, "passwd: malformed shadow line\n", 30); return 1; }

    if (uid != 0) {
        write(1, "Current password: ", 19);
        read_line(0, old_input, sizeof(old_input));
        if (!verify_old(old_input, sf[1])) {
            write(2, "passwd: authentication failed\n", 30); return 1;
        }
    }

    write(1, "New password: ", 14);
    read_line(0, new_input, sizeof(new_input));
    write(1, "Retype new password: ", 21);
    read_line(0, conf_input, sizeof(conf_input));
    if (strcmp(new_input, conf_input) != 0) {
        write(2, "passwd: passwords do not match\n", 31); return 1;
    }
    if ((long)strlen(new_input) < 6) {
        write(2, "passwd: password too short (min 6 chars)\n", 41); return 1;
    }

    make_salt(salt_buf, 8);
    long got = sha512crypt(new_input, salt_buf, 5000, hash_out);
    hash_out[got] = 0;

    long o = 0;
    memcpy(new_shadow_buf, shadow_buf, ls); o = ls;
    long n = strlen(target);     memcpy(new_shadow_buf + o, target, n); o += n;
    new_shadow_buf[o++] = ':';
    new_shadow_buf[o++] = '$'; new_shadow_buf[o++] = '6'; new_shadow_buf[o++] = '$';
    n = strlen(salt_buf);        memcpy(new_shadow_buf + o, salt_buf, n); o += n;
    new_shadow_buf[o++] = '$';
    n = strlen(hash_out);        memcpy(new_shadow_buf + o, hash_out, n); o += n;
    for (int fi = 2; fi <= 8 && fi < nf; fi++) {
        new_shadow_buf[o++] = ':';
        n = strlen(sf[fi]); memcpy(new_shadow_buf + o, sf[fi], n); o += n;
    }
    new_shadow_buf[o++] = '\n';
    long after = ls + ll;
    memcpy(new_shadow_buf + o, shadow_buf + after, sn - after); o += (sn - after);

    int nfd = open("/etc/shadow.new", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (nfd < 0) { write(2, "passwd: cannot open /etc/shadow.new\n", 36); return 1; }
    write(nfd, new_shadow_buf, o);
    close(nfd);
    if (rename("/etc/shadow.new", "/etc/shadow") < 0) {
        write(2, "passwd: rename failed\n", 22); return 1;
    }

    write(1, "passwd: password updated\n", 25);
    return 0;
}
