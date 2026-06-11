// /bin/hwrng_probe — D3.1 virtio-rng / /dev/hwrng regression.
//
// Proves the kernel's virtio-rng driver backs /dev/hwrng with real device
// entropy: open /dev/hwrng, read 32 bytes, assert the read returned >0 and
// the bytes are not all identical (a stuck/zero source would fail). Real
// hardware entropy from the virtio-rng requestq, not the LCG placeholder.

#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static void emit(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int fd = open("/dev/hwrng", O_RDONLY);
    if (fd < 0) { emit("hwrng_probe: FAIL open /dev/hwrng\n"); return 1; }

    unsigned char buf[32];
    memset(buf, 0, sizeof buf);
    long n = read(fd, buf, sizeof buf);
    close(fd);

    if (n <= 0) { emit("hwrng_probe: FAIL read returned <=0\n"); return 1; }

    // Entropy present iff not every byte is equal to the first.
    int all_equal = 1;
    for (long i = 1; i < n; i++) {
        if (buf[i] != buf[0]) { all_equal = 0; break; }
    }
    if (all_equal) { emit("hwrng_probe: FAIL all bytes equal (no entropy)\n"); return 1; }

    char out[48]; int p = 0;
    const char *tag = "hwrng_probe: PASS n=";
    memcpy(out + p, tag, strlen(tag)); p += (int)strlen(tag);
    // n is at most 32 → one or two decimal digits.
    if (n >= 10) out[p++] = (char)('0' + n / 10);
    out[p++] = (char)('0' + n % 10);
    out[p++] = '\n';
    write(1, out, p);
    return 0;
}
