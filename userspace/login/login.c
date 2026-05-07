// /bin/login — read username + password, verify against
// /etc/passwd + /etc/shadow, then execve(shell). Matches the v1
// crypt-stub: sha512(salt|password|salt) base64-encoded with
// the crypt(3) alphabet.
#include "../shared/oxide_start.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static int memeq(const char* a, const char* b, long n) {
    for (long i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}

#include "../shared/sha512crypt.h"

static int find_user_line(const char* text, const char* name, char* out, long cap) {
    long nl = strlen(name);
    long i = 0;
    while (text[i]) {
        long start = i;
        while (text[i] && text[i] != '\n') i++;
        long lnlen = i - start;
        if (lnlen > nl + 1 && text[start + nl] == ':' && memeq(text + start, name, nl)) {
            if (lnlen >= cap) return 0;
            memcpy(out, text + start, lnlen);
            out[lnlen] = 0;
            return 1;
        }
        if (text[i] == '\n') i++;
    }
    return 0;
}

static int split_colons(char* line, char** fields, int max) {
    int n = 0; fields[n++] = line;
    for (long i = 0; line[i]; i++) {
        if (line[i] == ':') {
            line[i] = 0;
            if (n < max) fields[n++] = &line[i+1];
        }
    }
    return n;
}

static char passwd_buf[8192];
static char shadow_buf[8192];
static char user_line[512];
static char user_input[64];
static char pw_input[128];
static char hash_out[128];

static long readall(int fd, char* buf, long cap) {
    long total = 0;
    while (total < cap - 1) {
        ssize_t n = read(fd, buf + total, cap - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = 0;
    return total;
}

static int read_line(int fd, char* dst, long cap) {
    long n = 0;
    while (n < cap - 1) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) break;
        if (c == '\n') break;
        dst[n++] = c;
    }
    dst[n] = 0;
    return (int)n;
}

int main(int argc, char** argv, char** envp) {
    (void)argc; (void)argv; (void)envp;
    write(1, "oxide login: ", 13);
    int ulen = read_line(0, user_input, sizeof(user_input));
    if (ulen <= 0) { write(2, "Login incorrect\n", 16); return 1; }

    write(1, "Password: ", 10);
    read_line(0, pw_input, sizeof(pw_input));

    int pfd = open("/etc/passwd", O_RDONLY);
    if (pfd < 0) { write(2, "no /etc/passwd\n", 15); return 1; }
    readall(pfd, passwd_buf, sizeof(passwd_buf));
    close(pfd);

    int sfd = open("/etc/shadow", O_RDONLY);
    if (sfd < 0) { write(2, "no /etc/shadow\n", 15); return 1; }
    readall(sfd, shadow_buf, sizeof(shadow_buf));
    close(sfd);

    if (!find_user_line(shadow_buf, user_input, user_line, sizeof(user_line))) {
        write(2, "Login incorrect\n", 16); return 1;
    }
    char* sf[8];
    int sn = split_colons(user_line, sf, 8);
    if (sn < 2) { write(2, "Login incorrect\n", 16); return 1; }
    char* hash = sf[1];

    if (hash[0] == 0) {
        if (pw_input[0] == 0) { /* allow */ }
        else                  { write(2, "Login incorrect\n", 16); return 1; }
    } else if (hash[0] == '!' || hash[0] == '*') {
        write(2, "Account locked\n", 15); return 1;
    } else if (hash[0] == '$' && hash[1] == '6' && hash[2] == '$') {
        long i = 3;
        while (hash[i] && hash[i] != '$') i++;
        if (!hash[i]) { write(2, "Login incorrect\n", 16); return 1; }
        hash[i] = 0;
        char* salt = &hash[3];
        char* expected = &hash[i+1];
        long got = sha512crypt(pw_input, salt, 5000, hash_out);
        hash_out[got] = 0;
        if (strcmp(hash_out, expected) != 0) {
            write(2, "Login incorrect\n", 16); return 1;
        }
    } else {
        write(2, "Unsupported hash format\n", 24); return 1;
    }

    if (!find_user_line(passwd_buf, user_input, user_line, sizeof(user_line))) {
        write(2, "Login incorrect\n", 16); return 1;
    }
    char* pf[8];
    int pn = split_colons(user_line, pf, 8);
    if (pn < 7) { write(2, "Login incorrect\n", 16); return 1; }
    char* shell = pf[6];

    write(1, "Welcome to oxide.\n", 18);
    char* exec_argv[2] = { shell, 0 };
    char* exec_envp[1] = { 0 };
    execve(shell, exec_argv, exec_envp);
    write(2, "exec failed\n", 12);
    return 1;
}
