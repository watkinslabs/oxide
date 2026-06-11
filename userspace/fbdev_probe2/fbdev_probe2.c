// /bin/fbdev_probe2 — D6 full fbdev semantics regression.
//
// Exercises the REAL (non-faked) FBIO* paths added in drivers-plan D6:
//   - FBIOGET_VSCREENINFO: real geometry.
//   - FBIOPUTCMAP / FBIOGETCMAP: the truecolor pseudo-palette — write 16
//     entries, read them back, assert the readback matches (proving a real,
//     persistent palette, not the old blanket EINVAL).
//   - FBIO_WAITFORVSYNC: real tick-driven pseudo-vblank — must return 0, and
//     two FBIOGET_VBLANK samples around a wait must see the count advance
//     (proving it is NOT an immediate fake).
//   - FBIOBLANK(POWERDOWN) then FBIOBLANK(UNBLANK): both return 0 (real
//     image-level blank + restore).
//   - FBIOPAN_DISPLAY(0,0): ok; a nonzero out-of-range offset: EINVAL (the
//     single console scanout keeps yres_virtual==yres, so any pan but (0,0)
//     is honestly rejected — never a silent no-op).
//
// Runs from a login shell via tools/boot-smoke-probe.sh (NOT the inline
// oxide-smokes loop) so the blank/unblank flicker doesn't disturb the
// console mid-boot.

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/ioctl.h>

#define FBIOGET_VSCREENINFO 0x4600
#define FBIOPUT_VSCREENINFO 0x4601
#define FBIOGETCMAP         0x4604
#define FBIOPUTCMAP         0x4605
#define FBIOPAN_DISPLAY     0x4606
#define FBIOBLANK           0x4611
#define FBIOGET_VBLANK      0x80204612
#define FBIO_WAITFORVSYNC   0x40044620

#define FB_BLANK_UNBLANK    0
#define FB_BLANK_POWERDOWN  4

struct fb_bitfield { uint32_t offset, length, msb_right; };
struct fb_var_screeninfo {
    uint32_t xres, yres, xres_virtual, yres_virtual, xoffset, yoffset;
    uint32_t bits_per_pixel, grayscale;
    struct fb_bitfield red, green, blue, transp;
    uint32_t nonstd, activate, height, width, accel_flags, pixclock;
    uint32_t left_margin, right_margin, upper_margin, lower_margin;
    uint32_t hsync_len, vsync_len, sync, vmode, rotate, colorspace;
    uint32_t reserved[4];
};
struct fb_cmap {
    uint32_t start, len;
    uint16_t *red, *green, *blue, *transp;
};
struct fb_vblank {
    uint32_t flags, count, vcount, hcount, reserved[4];
};

static void emit(const char *m) { write(1, m, strlen(m)); }
static int fail(const char *m) { emit(m); return 1; }

int main(void) {
    int fd = open("/dev/fb0", O_RDWR);
    if (fd < 0) return fail("fbdev_probe2: FAIL open\n");

    struct fb_var_screeninfo v; memset(&v, 0, sizeof v);
    if (ioctl(fd, FBIOGET_VSCREENINFO, &v) != 0)
        return fail("fbdev_probe2: FAIL VSCREENINFO\n");
    if (v.xres == 0 || v.yres == 0 || v.bits_per_pixel != 32)
        return fail("fbdev_probe2: FAIL geometry\n");

    // --- pseudo-palette: write 16 entries, read them back. Use entries of
    // the form 0xVVVV (low byte == high byte) so the 8-bit-per-channel
    // truecolor pack/unpack roundtrips exactly.
    uint16_t r[16], g[16], b[16], rr[16], gg[16], bb[16];
    for (int i = 0; i < 16; i++) {
        uint16_t s = (uint16_t)((i * 0x11) & 0xFF);
        r[i] = (uint16_t)((s << 8) | s);
        g[i] = (uint16_t)(((15 - i) * 0x11) << 8 | ((15 - i) * 0x11));
        b[i] = (uint16_t)((((i * 7) & 0xFF)) << 8 | ((i * 7) & 0xFF));
    }
    struct fb_cmap put = { 0, 16, r, g, b, 0 };
    if (ioctl(fd, FBIOPUTCMAP, &put) != 0)
        return fail("fbdev_probe2: FAIL PUTCMAP\n");
    memset(rr, 0, sizeof rr); memset(gg, 0, sizeof gg); memset(bb, 0, sizeof bb);
    struct fb_cmap get = { 0, 16, rr, gg, bb, 0 };
    if (ioctl(fd, FBIOGETCMAP, &get) != 0)
        return fail("fbdev_probe2: FAIL GETCMAP\n");
    for (int i = 0; i < 16; i++) {
        if (rr[i] != r[i] || gg[i] != g[i] || bb[i] != b[i])
            return fail("fbdev_probe2: FAIL cmap readback\n");
    }
    // start+len > 16 must be EINVAL (honest range check).
    struct fb_cmap oob = { 8, 16, r, g, b, 0 };
    if (ioctl(fd, FBIOPUTCMAP, &oob) == 0)
        return fail("fbdev_probe2: FAIL cmap oob accepted\n");

    // --- vsync: sample the counter, wait, sample again — must advance.
    struct fb_vblank vb0, vb1; memset(&vb0, 0, sizeof vb0); memset(&vb1, 0, sizeof vb1);
    if (ioctl(fd, FBIOGET_VBLANK, &vb0) != 0)
        return fail("fbdev_probe2: FAIL GET_VBLANK\n");
    if (ioctl(fd, FBIO_WAITFORVSYNC, 0) != 0)
        return fail("fbdev_probe2: FAIL WAITFORVSYNC\n");
    if (ioctl(fd, FBIOGET_VBLANK, &vb1) != 0)
        return fail("fbdev_probe2: FAIL GET_VBLANK 2\n");
    if (vb1.count == vb0.count)
        return fail("fbdev_probe2: FAIL vsync did not advance\n");

    // --- blank then unblank: both return 0 (real image-level blank/restore).
    if (ioctl(fd, FBIOBLANK, FB_BLANK_POWERDOWN) != 0)
        return fail("fbdev_probe2: FAIL BLANK powerdown\n");
    if (ioctl(fd, FBIOBLANK, FB_BLANK_UNBLANK) != 0)
        return fail("fbdev_probe2: FAIL BLANK unblank\n");

    // --- pan: (0,0) ok; an out-of-range yoffset is EINVAL (single buffer).
    struct fb_var_screeninfo pv = v;
    pv.xoffset = 0; pv.yoffset = 0;
    if (ioctl(fd, FBIOPAN_DISPLAY, &pv) != 0)
        return fail("fbdev_probe2: FAIL PAN 0,0\n");
    if (v.yres_virtual <= v.yres) {
        // No room to pan: a nonzero offset MUST be rejected, not no-op'd.
        struct fb_var_screeninfo bad = v; bad.yoffset = 1;
        if (ioctl(fd, FBIOPAN_DISPLAY, &bad) == 0)
            return fail("fbdev_probe2: FAIL pan nonzero accepted\n");
    }

    close(fd);
    emit("fbdev_probe2: PASS\n");
    return 0;
}
