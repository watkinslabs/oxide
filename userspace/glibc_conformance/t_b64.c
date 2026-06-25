#include <resolv.h>
#include <stdio.h>
#include <string.h>

static void show_hex(const unsigned char *buf, int n) {
    for (int i = 0; i < n; i++) {
        printf("%02x", buf[i]);
    }
}

static void enc(const char *label, const unsigned char *src, size_t len, size_t cap) {
    char out[64];
    memset(out, 'X', sizeof(out));
    int r = b64_ntop(src, len, out, cap);
    printf("enc %s len=%zu cap=%zu r=%d", label, len, cap, r);
    if (r >= 0) {
        printf(" out=%s", out);
    }
    putchar('\n');
}

static void dec(const char *src, size_t cap) {
    unsigned char out[64];
    memset(out, 0xaa, sizeof(out));
    int r = b64_pton(src, out, cap);
    printf("dec [%s] cap=%zu r=%d", src, cap, r);
    if (r >= 0) {
        printf(" bytes=");
        show_hex(out, r);
    }
    putchar('\n');
}

int main(void) {
    const unsigned char empty[] = "";
    const unsigned char hello[] = "hello";
    const unsigned char bytes[] = {0x00, 0x01, 0x02, 0xfd, 0xfe, 0xff};

    enc("empty", empty, 0, sizeof((char[64]){0}));
    enc("hello", hello, 5, sizeof((char[64]){0}));
    enc("bytes", bytes, sizeof(bytes), sizeof((char[64]){0}));
    enc("small", hello, 5, 4);

    dec("", sizeof((unsigned char[64]){0}));
    dec("aGVsbG8=", sizeof((unsigned char[64]){0}));
    dec("AAEC/f7/", sizeof((unsigned char[64]){0}));
    dec("YQ==", sizeof((unsigned char[64]){0}));
    dec("YWI=", sizeof((unsigned char[64]){0}));
    dec("YWJj", sizeof((unsigned char[64]){0}));
    dec("Y W\nJj", sizeof((unsigned char[64]){0}));
    dec("YQ", sizeof((unsigned char[64]){0}));
    dec("YQ==AA", sizeof((unsigned char[64]){0}));
    dec("aGVsbG8=", 4);
    return 0;
}
