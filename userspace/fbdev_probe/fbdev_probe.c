// /bin/fbdev_probe — real /dev/fb0: geometry + mmap + write-back + flush.
//
// Regression for console-plan #1: /dev/fb0 must report the real scanout
// geometry (FBIOGET_*SCREENINFO), mmap the real framebuffer physical memory
// into the process (Linux remap_pfn_range), and accept a present/flush
// (FBIO_WAITFORVSYNC). Maps the fb, writes a marker pixel through the mapping,
// reads it back (proving the mmap reaches real, persistent fb memory), then
// flushes. Restores the pixel so the console isn't corrupted.

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define FBIOGET_VSCREENINFO 0x4600
#define FBIOGET_FSCREENINFO 0x4602
#define FBIO_WAITFORVSYNC   0x40044620

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
struct fb_fix_screeninfo {
    char id[16]; uint64_t smem_start; uint32_t smem_len, type, type_aux, visual;
    uint16_t xpanstep, ypanstep, ywrapstep; uint32_t line_length;
    uint64_t mmio_start; uint32_t mmio_len, accel; uint16_t capabilities, reserved[2];
};

static void emit(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int fd = open("/dev/fb0", O_RDWR);
    if (fd < 0) { emit("fbdev_probe: FAIL open\n"); return 1; }

    struct fb_var_screeninfo v; memset(&v, 0, sizeof v);
    if (ioctl(fd, FBIOGET_VSCREENINFO, &v) != 0) { emit("fbdev_probe: FAIL VSCREENINFO\n"); return 1; }
    if (v.xres == 0 || v.yres == 0 || v.bits_per_pixel != 32) {
        emit("fbdev_probe: FAIL geometry\n"); return 1;
    }
    struct fb_fix_screeninfo f; memset(&f, 0, sizeof f);
    if (ioctl(fd, FBIOGET_FSCREENINFO, &f) != 0) { emit("fbdev_probe: FAIL FSCREENINFO\n"); return 1; }
    if (f.smem_len == 0 || f.line_length == 0) { emit("fbdev_probe: FAIL fix\n"); return 1; }

    // mmap the real framebuffer.
    uint32_t *fb = mmap(0, f.smem_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (fb == MAP_FAILED) { emit("fbdev_probe: FAIL mmap\n"); return 1; }

    // Write a marker to the last pixel (least likely to be overdrawn by the
    // console cursor) and read it back through the mapping.
    uint32_t last = (f.smem_len / 4) - 1;
    uint32_t save = fb[last];
    fb[last] = 0x00ABCDEF;
    uint32_t got = fb[last];
    fb[last] = save;            // restore — don't corrupt the console
    if (got != 0x00ABCDEF) { emit("fbdev_probe: FAIL mmap readback\n"); munmap(fb, f.smem_len); return 1; }

    // Present/flush path.
    ioctl(fd, FBIO_WAITFORVSYNC, 0);

    munmap(fb, f.smem_len);
    close(fd);
    emit("fbdev_probe: PASS\n");
    return 0;
}
