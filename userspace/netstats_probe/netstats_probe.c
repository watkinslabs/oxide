// /bin/netstats_probe — D7b virtio-net statistics regression.
//
// Proves /sys/class/net/eth0/statistics/ is a real subdirectory backed by the
// live virtio-net NetDev::stats() counters: every standard stat file exists +
// parses as a decimal (the full Linux statistics surface, not one token or a
// stub). The values themselves move under real traffic — that's exercised by
// make smoke-dhcp-x86 / smoke-ssh-x86 (DHCP + TCP drive the bumped tx_frame /
// rx_poll counters); here we assert the surface is real + complete.
// Prints "netstats_probe: PASS rx_packets=N tx_packets=M".

#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static void emit(const char *m) { write(1, m, strlen(m)); }

// Read a statistics field; *ok=1 iff the file existed and parsed to a decimal.
static long read_stat(const char *base, const char *field, int *ok) {
    char p[96];
    strcpy(p, base); strcat(p, "/"); strcat(p, field);
    *ok = 0;
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    char buf[32];
    long n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    long v = 0; int sawdigit = 0;
    for (long i = 0; i < n; i++) {
        char c = buf[i];
        if (c < '0' || c > '9') break;
        v = v * 10 + (c - '0'); sawdigit = 1;
    }
    if (!sawdigit) return -1;
    *ok = 1;
    return v;
}

static void putdec(char *buf, int *pos, long v) {
    char tmp[24]; int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v > 0) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    while (n) buf[(*pos)++] = tmp[--n];
}

int main(void) {
    const char *base = "/sys/class/net/eth0/statistics";
    // The full standard counter set must exist + parse (a real statistics dir,
    // not a single stubbed file).
    static const char *fields[] = {
        "rx_packets", "rx_bytes", "rx_errors", "rx_dropped",
        "tx_packets", "tx_bytes", "tx_errors", "tx_dropped",
    };
    long rx_packets = 0, tx_packets = 0;
    for (int i = 0; i < 8; i++) {
        int ok;
        long v = read_stat(base, fields[i], &ok);
        if (!ok) {
            emit("netstats_probe: FAIL field missing/unparsable: ");
            emit(fields[i]); emit("\n");
            return 1;
        }
        if (i == 0) rx_packets = v;
        if (i == 4) tx_packets = v;
    }

    char out[96]; int q = 0;
    const char *tag = "netstats_probe: PASS rx_packets=";
    memcpy(out + q, tag, strlen(tag)); q += (int)strlen(tag);
    putdec(out, &q, rx_packets);
    const char *t2 = " tx_packets="; memcpy(out + q, t2, strlen(t2)); q += (int)strlen(t2);
    putdec(out, &q, tx_packets);
    out[q++] = '\n';
    write(1, out, q);
    return 0;
}
