// /bin/kdfont_probe — KDFONTOP + GIO_UNIMAP ioctl glue (setfont path).
//
// Regression for console-plan #6b: the kernel must marshal console_font_op
// (KD_FONT_OP_GET returns the live font dims + bitmaps) and unimapdesc
// (GIO_UNIMAP returns the conv_uni_to_pc map). Reads the built-in default
// font (8x16, 256 glyphs) and its unicode map, then KD_FONT_OP_SET_DEFAULT —
// exercising the struct/pointer marshalling the host tests can't.

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>

#define KDFONTOP   0x4B72
#define GIO_UNIMAP 0x4B66
#define KD_FONT_OP_SET_DEFAULT 2
#define KD_FONT_OP_GET 1

struct console_font_op { unsigned int op, flags, width, height, charcount; unsigned char *data; };
struct unipair { unsigned short unicode, fontpos; };
struct unimapdesc { unsigned short entry_ct; struct unipair *entries; };

static void emit(const char *m) { write(1, m, strlen(m)); }

static unsigned char fbuf[512 * 32];
static struct unipair upairs[512];

int main(void) {
    int fd = open("/dev/tty0", O_RDWR);
    if (fd < 0) fd = 0;

    // KD_FONT_OP_GET: read the live font (the built-in default8x16).
    struct console_font_op op;
    memset(&op, 0, sizeof op);
    op.op = KD_FONT_OP_GET; op.charcount = 512; op.data = fbuf;
    if (ioctl(fd, KDFONTOP, &op) != 0) { emit("kdfont_probe: FAIL KD_FONT_OP_GET\n"); return 1; }
    if (op.width != 8 || op.height != 16 || op.charcount != 256) {
        emit("kdfont_probe: FAIL font dims\n"); return 1;
    }

    // GIO_UNIMAP: the conv_uni_to_pc map must be non-trivial (CP437 ~280).
    struct unimapdesc d; d.entry_ct = 512; d.entries = upairs;
    if (ioctl(fd, GIO_UNIMAP, &d) != 0) { emit("kdfont_probe: FAIL GIO_UNIMAP\n"); return 1; }
    if (d.entry_ct < 100) { emit("kdfont_probe: FAIL unimap too small\n"); return 1; }

    // KD_FONT_OP_SET_DEFAULT: restore the built-in font (leave console sane).
    struct console_font_op sd; memset(&sd, 0, sizeof sd);
    sd.op = KD_FONT_OP_SET_DEFAULT;
    if (ioctl(fd, KDFONTOP, &sd) != 0) { emit("kdfont_probe: FAIL SET_DEFAULT\n"); return 1; }

    emit("kdfont_probe: PASS\n");
    return 0;
}
