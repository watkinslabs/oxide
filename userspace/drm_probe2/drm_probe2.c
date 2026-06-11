// /bin/drm_probe2 — D5b-1 DRM dumb-buffer + mmap + ADDFB2 regression.
//
// Proves the offscreen half of D5b: CREATE_DUMB allocates real
// contiguous pages, MAP_DUMB hands back an mmap cookie, mmap() maps the
// physical buffer into the process (VmaBacking::PhysRange), a write +
// readback through that mapping round-trips (proving the mapping is
// live), ADDFB2 builds an FB object referencing the handle, then RMFB +
// DESTROY_DUMB tear it all down. NO SETCRTC / scanout (that's D5b-2);
// the fb console is untouched.
//
// musl ships no libdrm; the ioctl numbers + struct layouts are defined
// inline, copied from linux/include/uapi/drm/drm_mode.h EXACTLY.

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

static void emit(const char *m) { write(1, m, strlen(m)); }

// DRM ioctl base is 'd' == 0x64.
#define DRM_IOCTL_MODE_CREATE_DUMB   _IOWR(0x64, 0xb2, struct drm_mode_create_dumb)
#define DRM_IOCTL_MODE_MAP_DUMB      _IOWR(0x64, 0xb3, struct drm_mode_map_dumb)
#define DRM_IOCTL_MODE_DESTROY_DUMB  _IOWR(0x64, 0xb4, struct drm_mode_destroy_dumb)
#define DRM_IOCTL_MODE_ADDFB2        _IOWR(0x64, 0xb8, struct drm_mode_fb_cmd2)
#define DRM_IOCTL_MODE_RMFB          _IOWR(0x64, 0xaf, unsigned int)

#define DRM_FORMAT_XRGB8888 0x34325258  // 'XR24'

struct drm_mode_create_dumb {
    uint32_t height;
    uint32_t width;
    uint32_t bpp;
    uint32_t flags;
    uint32_t handle;
    uint32_t pitch;
    uint64_t size;
};

struct drm_mode_map_dumb {
    uint32_t handle;
    uint32_t pad;
    uint64_t offset;
};

struct drm_mode_destroy_dumb {
    uint32_t handle;
};

struct drm_mode_fb_cmd2 {
    uint32_t fb_id;
    uint32_t width;
    uint32_t height;
    uint32_t pixel_format;
    uint32_t flags;
    uint32_t handles[4];
    uint32_t pitches[4];
    uint32_t offsets[4];
    uint64_t modifier[4];
};

int main(void) {
    int fd = open("/dev/dri/card0", O_RDWR);
    if (fd < 0) { emit("drm_probe2: FAIL open /dev/dri/card0\n"); return 1; }

    // ---- 1. CREATE_DUMB 640x480x32 ----
    struct drm_mode_create_dumb cd;
    memset(&cd, 0, sizeof cd);
    cd.width = 640; cd.height = 480; cd.bpp = 32;
    if (ioctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &cd) < 0) {
        emit("drm_probe2: FAIL CREATE_DUMB\n"); close(fd); return 1;
    }
    if (cd.handle == 0 || cd.pitch < 640 * 4 || cd.size < (uint64_t)cd.pitch * 480) {
        emit("drm_probe2: FAIL bad create result\n"); close(fd); return 1;
    }

    // ---- 2. MAP_DUMB → cookie ----
    struct drm_mode_map_dumb md;
    memset(&md, 0, sizeof md);
    md.handle = cd.handle;
    if (ioctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &md) < 0) {
        emit("drm_probe2: FAIL MAP_DUMB\n"); close(fd); return 1;
    }

    // ---- 3. mmap the buffer, write a pattern, read it back ----
    volatile uint32_t *px = mmap(0, cd.size, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, fd, md.offset);
    if (px == MAP_FAILED) {
        emit("drm_probe2: FAIL mmap\n"); close(fd); return 1;
    }
    px[0]    = 0xFF00FF00;
    px[1000] = 0x12345678;
    if (px[0] != 0xFF00FF00 || px[1000] != 0x12345678) {
        emit("drm_probe2: FAIL mmap readback\n");
        munmap((void *)px, cd.size); close(fd); return 1;
    }
    munmap((void *)px, cd.size);

    // ---- 4. ADDFB2 referencing the handle ----
    struct drm_mode_fb_cmd2 fb;
    memset(&fb, 0, sizeof fb);
    fb.width = 640; fb.height = 480;
    fb.pixel_format = DRM_FORMAT_XRGB8888;
    fb.handles[0] = cd.handle;
    fb.pitches[0] = cd.pitch;
    if (ioctl(fd, DRM_IOCTL_MODE_ADDFB2, &fb) < 0 || fb.fb_id == 0) {
        emit("drm_probe2: FAIL ADDFB2\n"); close(fd); return 1;
    }

    // ---- 5. RMFB ----
    unsigned int fb_id = fb.fb_id;
    if (ioctl(fd, DRM_IOCTL_MODE_RMFB, &fb_id) < 0) {
        emit("drm_probe2: FAIL RMFB\n"); close(fd); return 1;
    }

    // ---- 6. DESTROY_DUMB ----
    struct drm_mode_destroy_dumb dd;
    memset(&dd, 0, sizeof dd);
    dd.handle = cd.handle;
    if (ioctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &dd) < 0) {
        emit("drm_probe2: FAIL DESTROY_DUMB\n"); close(fd); return 1;
    }
    close(fd);

    emit("drm_probe2: PASS\n");
    return 0;
}
