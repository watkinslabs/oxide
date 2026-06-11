// /bin/vcs_probe — /dev/vcs + /dev/vcsa screen-dump devices.
//
// Regression for console-plan #7: reading /dev/vcs0 returns the foreground
// VT's screen text; /dev/vcsa0 prefixes a 4-byte header [rows, cols, x, y]
// then [glyph, attr] pairs (Linux vc_screen.c). Confirms a non-empty screen
// dump and a sane vcsa header.

#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static void emit(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    // /dev/vcs0: raw screen glyphs (rows*cols bytes). The console has printed
    // boot text, so the dump must be non-empty and hold a printable char.
    int fd = open("/dev/vcs0", O_RDONLY);
    if (fd < 0) { emit("vcs_probe: FAIL open vcs0\n"); return 1; }
    char buf[256];
    long n = read(fd, buf, sizeof buf);
    close(fd);
    if (n <= 0) { emit("vcs_probe: FAIL vcs0 empty\n"); return 1; }
    int printable = 0;
    for (long i = 0; i < n; i++) if (buf[i] > 0x20 && buf[i] < 0x7f) { printable = 1; break; }
    if (!printable) { emit("vcs_probe: FAIL vcs0 blank\n"); return 1; }

    // /dev/vcsa0: 4-byte header [rows, cols, cursor_x, cursor_y].
    int fa = open("/dev/vcsa0", O_RDONLY);
    if (fa < 0) { emit("vcs_probe: FAIL open vcsa0\n"); return 1; }
    unsigned char hdr[4] = {0,0,0,0};
    long m = read(fa, hdr, 4);
    close(fa);
    if (m < 4 || hdr[0] == 0 || hdr[1] == 0) { emit("vcs_probe: FAIL vcsa header\n"); return 1; }

    emit("vcs_probe: PASS\n");
    return 0;
}
