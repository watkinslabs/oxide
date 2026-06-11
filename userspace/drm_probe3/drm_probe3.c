// /bin/drm_probe3 — D5b-2 DRM SETCRTC scanout regression.
//
// Proves the kernel scans out a userspace dumb buffer through
// virtio-gpu: enumerate (GETRESOURCES → crtc0/connector0, GETCONNECTOR
// → the preferred mode), CREATE_DUMB(mode.w, mode.h, 32), MAP_DUMB +
// mmap, paint a solid color, ADDFB2 → fb_id, then
// SETCRTC(crtc0, fb_id, 0,0, &connector0, 1, mode) and assert rv == 0.
// Prints "drm_probe3: PASS WxH" iff SETCRTC succeeds, then exits —
// closing card0 fires the kernel's on_release which restores the fb
// console scanout (so getty/login come back).
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

// _IOWR(0x64, nr, type) — DRM ioctl base is 'd' == 0x64.
#define DRM_IOCTL_MODE_GETRESOURCES  _IOWR(0x64, 0xa0, struct drm_mode_card_res)
#define DRM_IOCTL_MODE_SETCRTC       _IOWR(0x64, 0xa2, struct drm_mode_crtc)
#define DRM_IOCTL_MODE_GETCONNECTOR  _IOWR(0x64, 0xa7, struct drm_mode_get_connector)
#define DRM_IOCTL_MODE_CREATE_DUMB   _IOWR(0x64, 0xb2, struct drm_mode_create_dumb)
#define DRM_IOCTL_MODE_MAP_DUMB      _IOWR(0x64, 0xb3, struct drm_mode_map_dumb)
#define DRM_IOCTL_MODE_ADDFB2        _IOWR(0x64, 0xb8, struct drm_mode_fb_cmd2)

#define DRM_FORMAT_XRGB8888 0x34325258  // 'XR24'
#define DRM_MODE_CONNECTED 1

struct drm_mode_card_res {
    uint64_t fb_id_ptr;
    uint64_t crtc_id_ptr;
    uint64_t connector_id_ptr;
    uint64_t encoder_id_ptr;
    uint32_t count_fbs;
    uint32_t count_crtcs;
    uint32_t count_connectors;
    uint32_t count_encoders;
    uint32_t min_width, max_width;
    uint32_t min_height, max_height;
};

struct drm_mode_modeinfo {
    uint32_t clock;
    uint16_t hdisplay, hsync_start, hsync_end, htotal, hskew;
    uint16_t vdisplay, vsync_start, vsync_end, vtotal, vscan;
    uint32_t vrefresh;
    uint32_t flags;
    uint32_t type;
    char     name[32];
};

struct drm_mode_crtc {
    uint64_t set_connectors_ptr;
    uint32_t count_connectors;
    uint32_t crtc_id;
    uint32_t fb_id;
    uint32_t x, y;
    uint32_t gamma_size;
    uint32_t mode_valid;
    struct drm_mode_modeinfo mode;
};

struct drm_mode_get_connector {
    uint64_t encoders_ptr;
    uint64_t modes_ptr;
    uint64_t props_ptr;
    uint64_t prop_values_ptr;
    uint32_t count_modes;
    uint32_t count_props;
    uint32_t count_encoders;
    uint32_t encoder_id;
    uint32_t connector_id;
    uint32_t connector_type;
    uint32_t connector_type_id;
    uint32_t connection;
    uint32_t mm_width, mm_height;
    uint32_t subpixel;
    uint32_t pad;
};

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

static int putdec(char *p, unsigned v) {
    char tmp[10]; int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    for (int i = 0; i < n; i++) p[i] = tmp[n - 1 - i];
    return n;
}

int main(void) {
    int fd = open("/dev/dri/card0", O_RDWR);
    if (fd < 0) { emit("drm_probe3: FAIL open /dev/dri/card0\n"); return 1; }

    // ---- 1. GETRESOURCES: crtc0 + connector0 ----
    uint32_t crtcs[16], conns[16];
    struct drm_mode_card_res res;
    memset(&res, 0, sizeof res);
    if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0
        || res.count_crtcs < 1 || res.count_connectors < 1) {
        emit("drm_probe3: FAIL GETRESOURCES\n"); close(fd); return 1;
    }
    if (res.count_crtcs > 16 || res.count_connectors > 16) {
        emit("drm_probe3: FAIL too many objects\n"); close(fd); return 1;
    }
    res.crtc_id_ptr      = (uint64_t)(uintptr_t)crtcs;
    res.connector_id_ptr = (uint64_t)(uintptr_t)conns;
    if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) {
        emit("drm_probe3: FAIL GETRESOURCES pass2\n"); close(fd); return 1;
    }

    // ---- 2. GETCONNECTOR: the preferred mode ----
    struct drm_mode_modeinfo modes[16];
    struct drm_mode_get_connector conn;
    memset(&conn, 0, sizeof conn);
    conn.connector_id = conns[0];
    conn.count_modes  = 16;
    conn.modes_ptr    = (uint64_t)(uintptr_t)modes;
    if (ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) < 0
        || conn.connection != DRM_MODE_CONNECTED || conn.count_modes < 1) {
        emit("drm_probe3: FAIL GETCONNECTOR\n"); close(fd); return 1;
    }
    unsigned w = modes[0].hdisplay, h = modes[0].vdisplay;
    if (w < 1 || h < 1 || w > 8192 || h > 8192) {
        emit("drm_probe3: FAIL insane mode dims\n"); close(fd); return 1;
    }

    // ---- 3. CREATE_DUMB at the mode size ----
    struct drm_mode_create_dumb cd;
    memset(&cd, 0, sizeof cd);
    cd.width = w; cd.height = h; cd.bpp = 32;
    if (ioctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &cd) < 0 || cd.handle == 0) {
        emit("drm_probe3: FAIL CREATE_DUMB\n"); close(fd); return 1;
    }

    // ---- 4. MAP_DUMB + mmap + paint solid red ----
    struct drm_mode_map_dumb md;
    memset(&md, 0, sizeof md);
    md.handle = cd.handle;
    if (ioctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &md) < 0) {
        emit("drm_probe3: FAIL MAP_DUMB\n"); close(fd); return 1;
    }
    volatile uint32_t *px = mmap(0, cd.size, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, fd, md.offset);
    if (px == MAP_FAILED) {
        emit("drm_probe3: FAIL mmap\n"); close(fd); return 1;
    }
    // XRGB8888 little-endian: 0x00RRGGBB. Solid red.
    unsigned pxcount = (cd.pitch / 4) * h;
    for (unsigned i = 0; i < pxcount; i++) px[i] = 0x00FF0000;
    munmap((void *)px, cd.size);

    // ---- 5. ADDFB2 referencing the handle ----
    struct drm_mode_fb_cmd2 fb;
    memset(&fb, 0, sizeof fb);
    fb.width = w; fb.height = h;
    fb.pixel_format = DRM_FORMAT_XRGB8888;
    fb.handles[0] = cd.handle;
    fb.pitches[0] = cd.pitch;
    if (ioctl(fd, DRM_IOCTL_MODE_ADDFB2, &fb) < 0 || fb.fb_id == 0) {
        emit("drm_probe3: FAIL ADDFB2\n"); close(fd); return 1;
    }

    // ---- 6. SETCRTC(crtc0, fb_id, 0,0, &connector0, 1, mode) ----
    uint32_t conn0 = conns[0];
    struct drm_mode_crtc sc;
    memset(&sc, 0, sizeof sc);
    sc.crtc_id            = crtcs[0];
    sc.fb_id              = fb.fb_id;
    sc.x                  = 0;
    sc.y                  = 0;
    sc.set_connectors_ptr = (uint64_t)(uintptr_t)&conn0;
    sc.count_connectors   = 1;
    sc.mode_valid         = 1;
    sc.mode               = modes[0];
    if (ioctl(fd, DRM_IOCTL_MODE_SETCRTC, &sc) != 0) {
        emit("drm_probe3: FAIL SETCRTC\n"); close(fd); return 1;
    }

    char out[64]; int p = 0;
    const char *t = "drm_probe3: PASS ";
    memcpy(out + p, t, strlen(t)); p += (int)strlen(t);
    p += putdec(out + p, w); out[p++] = 'x'; p += putdec(out + p, h);
    out[p++] = '\n';
    write(1, out, p);

    // Closing card0 here fires DrmCardInode::on_release → the kernel
    // restores the fb-console scanout so getty/login return.
    close(fd);
    return 0;
}
