// /bin/passwd — change a user's password.
//
// Usage:
//   passwd [<user>]
//
// Without args, changes the calling user's password (uid lookup
// via /etc/passwd). With <user>, only root may change someone
// else's. Flow:
//   1. Look up target's /etc/shadow line.
//   2. If non-root + non-empty hash, prompt for current password
//      and verify via crypt::verify (Drepper sha512crypt).
//   3. Prompt for new password twice; reject mismatch.
//   4. Generate a 8-char random salt from /dev/urandom (or fall
//      back to the seconds-since-epoch hex digest).
//   5. Compute $6$<salt>$<hash> via Drepper sha512crypt.
//   6. Atomically rewrite /etc/shadow by:
//        write new content to /etc/shadow.new, rename → /etc/shadow.
//
// v1 limits:
//   - PAM `passwd` stack not consulted (only checks UnixAccount in
//     pam crate's defaults; passwords are always changeable today)
//   - shadow file size cap 16 KB
//   - no aging logic (lastchg field not updated)

#include <sys/syscall.h>
#include <stdint.h>

#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT  0100
#define O_TRUNC  01000
#define AT_FDCWD -100

static long sc1(long n, long a) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a) : "rcx","r11","memory"); return r;
}
static long sc2(long n, long a, long b) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b) : "rcx","r11","memory"); return r;
}
static long sc3(long n, long a, long b, long c) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c) : "rcx","r11","memory"); return r;
}
static long sc4(long n, long a, long b, long c, long d) {
    long r; register long r10 __asm__("r10") = d;
    __asm__ volatile ("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx","r11","memory");
    return r;
}

static long mlen(const char* s) { long n = 0; while (s[n]) n++; return n; }
static void wstr(int fd, const char* s) { sc3(SYS_write, fd, (long)s, mlen(s)); }
static int  streq(const char* a, const char* b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}
static int memeq(const char* a, const char* b, long n) {
    for (long i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static int read_line(int fd, char* dst, long cap) {
    long n = 0;
    while (n < cap - 1) {
        char c; long r = sc3(SYS_read, fd, (long)&c, 1);
        if (r <= 0) break;
        if (c == '\n') break;
        dst[n++] = c;
    }
    dst[n] = 0; return (int)n;
}

#include "../shared/sha512crypt.h"

// Find a `name:`-prefixed line in `text`. Stores raw line (incl.
// '\n' if present) bounds via *start_out / *len_out. Returns 1 if
// found. Used both for read + replace path.
static int find_line(const char* text, long total, const char* name,
                     long* start_out, long* len_out)
{
    long nl = mlen(name);
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
    if (hash[0] == 0) return 1; // empty = no password set
    if (hash[0] == '!' || hash[0] == '*') return 0; // locked
    if (hash[0] != '$' || hash[1] != '6' || hash[2] != '$') return 0;
    // hash = $6$<salt>$<expected>
    char buf[160];
    long n = mlen(hash);
    if (n >= (long)sizeof(buf)) return 0;
    for (long i = 0; i < n; i++) buf[i] = hash[i];
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
    return streq(computed, expected);
}

// Generate an 8-char salt drawn from /dev/urandom mapped through
// the crypt-base64 alphabet. Falls back to time-based bytes if
// /dev/urandom isn't available.
static void make_salt(char* out, long n) {
    uint8_t raw[16];
    long fd = sc4(SYS_openat, AT_FDCWD, (long)"/dev/urandom", 0, 0);
    if (fd >= 0) {
        sc3(SYS_read, fd, (long)raw, 16);
        sc1(SYS_close, fd);
    } else {
        // Fallback: clock_gettime(CLOCK_MONOTONIC) + xorshift.
        struct { long sec; long nsec; } ts; ts.sec = 0; ts.nsec = 0;
        sc2(SYS_clock_gettime, 1, (long)&ts);
        uint64_t x = (uint64_t)ts.nsec ^ ((uint64_t)ts.sec << 32);
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

__attribute__((force_align_arg_pointer))
void _start(void) {
    long argc; char** argv;
    __asm__ volatile ("mov (%%rsp), %0\n\t lea 8(%%rsp), %1\n\t"
                      : "=r"(argc), "=r"(argv));

    long uid = sc1(SYS_getuid, 0);
    char self_name[64] = "?";

    long pfd = sc4(SYS_openat, AT_FDCWD, (long)"/etc/passwd", O_RDONLY, 0);
    if (pfd < 0) { wstr(2, "passwd: cannot open /etc/passwd\n"); sc1(SYS_exit, 1); }
    long pn = 0;
    while (pn < (long)sizeof(passwd_buf) - 1) {
        long r = sc3(SYS_read, pfd, (long)(passwd_buf + pn), sizeof(passwd_buf) - 1 - pn);
        if (r <= 0) break; pn += r;
    }
    sc1(SYS_close, pfd);
    passwd_buf[pn] = 0;

    // Find self by uid (parse field 3) for default-user behavior.
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
    if (uid != 0 && !streq(target, self_name)) {
        wstr(2, "passwd: only root may change another user\n");
        sc1(SYS_exit, 1);
    }

    long sfd = sc4(SYS_openat, AT_FDCWD, (long)"/etc/shadow", O_RDONLY, 0);
    if (sfd < 0) { wstr(2, "passwd: cannot open /etc/shadow\n"); sc1(SYS_exit, 1); }
    long sn = 0;
    while (sn < (long)sizeof(shadow_buf) - 1) {
        long r = sc3(SYS_read, sfd, (long)(shadow_buf + sn), sizeof(shadow_buf) - 1 - sn);
        if (r <= 0) break; sn += r;
    }
    sc1(SYS_close, sfd);
    shadow_buf[sn] = 0;

    long ls, ll;
    if (!find_line(shadow_buf, sn, target, &ls, &ll)) {
        wstr(2, "passwd: no shadow entry for user\n"); sc1(SYS_exit, 1);
    }

    // Copy line out for split.
    char line_buf[1024];
    long copy_len = ll;
    if (copy_len > 0 && shadow_buf[ls + copy_len - 1] == '\n') copy_len--;
    if (copy_len >= (long)sizeof(line_buf)) { wstr(2, "passwd: line too long\n"); sc1(SYS_exit, 1); }
    for (long i = 0; i < copy_len; i++) line_buf[i] = shadow_buf[ls + i];
    line_buf[copy_len] = 0;
    char* sf[12];
    int nf = split_colons(line_buf, sf, 12);
    if (nf < 9) { wstr(2, "passwd: malformed shadow line\n"); sc1(SYS_exit, 1); }

    // Verify old password unless root or empty hash.
    if (uid != 0) {
        wstr(1, "Current password: ");
        read_line(0, old_input, sizeof(old_input));
        if (!verify_old(old_input, sf[1])) {
            wstr(2, "passwd: authentication failed\n"); sc1(SYS_exit, 1);
        }
    }

    wstr(1, "New password: ");
    read_line(0, new_input, sizeof(new_input));
    wstr(1, "Retype new password: ");
    read_line(0, conf_input, sizeof(conf_input));
    if (!streq(new_input, conf_input)) {
        wstr(2, "passwd: passwords do not match\n"); sc1(SYS_exit, 1);
    }
    if (mlen(new_input) < 6) {
        wstr(2, "passwd: password too short (min 6 chars)\n"); sc1(SYS_exit, 1);
    }

    make_salt(salt_buf, 8);
    long got = sha512crypt(new_input, salt_buf, 5000, hash_out);
    hash_out[got] = 0;

    // Build new shadow content: copy bytes up to ls, write new line, then bytes after ls+ll.
    long o = 0;
    for (long i = 0; i < ls; i++) new_shadow_buf[o++] = shadow_buf[i];
    // <name>:$6$<salt>$<hash>:lastchg:min:max:warn:inactive:expire:reserved
    long n = mlen(target);     for (long i = 0; i < n; i++) new_shadow_buf[o++] = target[i];
    new_shadow_buf[o++] = ':';
    new_shadow_buf[o++] = '$'; new_shadow_buf[o++] = '6'; new_shadow_buf[o++] = '$';
    n = mlen(salt_buf);        for (long i = 0; i < n; i++) new_shadow_buf[o++] = salt_buf[i];
    new_shadow_buf[o++] = '$';
    n = mlen(hash_out);        for (long i = 0; i < n; i++) new_shadow_buf[o++] = hash_out[i];
    // Re-emit original fields 2..8 (lastchg .. reserved).
    for (int fi = 2; fi <= 8 && fi < nf; fi++) {
        new_shadow_buf[o++] = ':';
        n = mlen(sf[fi]); for (long i = 0; i < n; i++) new_shadow_buf[o++] = sf[fi][i];
    }
    new_shadow_buf[o++] = '\n';
    long after = ls + ll;
    for (long i = after; i < sn; i++) new_shadow_buf[o++] = shadow_buf[i];

    // Write to /etc/shadow.new, then rename.
    long nfd = sc4(SYS_openat, AT_FDCWD, (long)"/etc/shadow.new",
                   O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (nfd < 0) { wstr(2, "passwd: cannot open /etc/shadow.new\n"); sc1(SYS_exit, 1); }
    sc3(SYS_write, nfd, (long)new_shadow_buf, o);
    sc1(SYS_close, nfd);
    if (sc3(SYS_rename, (long)"/etc/shadow.new", (long)"/etc/shadow", 0) < 0) {
        wstr(2, "passwd: rename failed\n"); sc1(SYS_exit, 1);
    }

    wstr(1, "passwd: password updated\n");
    sc1(SYS_exit, 0);
    __builtin_unreachable();
}
