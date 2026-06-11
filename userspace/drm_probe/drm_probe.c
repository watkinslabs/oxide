// /bin/drm_probe — D5a real DRM/KMS modeset-info regression.
//
// Proves the kernel's DRM card node returns REAL CRTC/connector/encoder
// objects built from the virtio-gpu display info (not counts-only +
// EINVAL). Opens /dev/dri/card0, then:
//   1. MODE_GETRESOURCES 2-pass (learn counts, alloc, fetch ids) →
//      assert >=1 crtc / connector / encoder.
//   2. MODE_GETCONNECTOR 2-pass for the mode list → assert connected
//      + >=1 mode with sane width/height.
//   3. MODE_GETCRTC + MODE_GETENCODER on the first ids → assert no error.
// Prints "drm_probe: PASS res=WxH crtcs=N conns=N" iff all succeed.
//
// musl ships no libdrm; the ioctl numbers + struct layouts are defined
// inline, copied from linux/include/uapi/drm/drm_mode.h EXACTLY.

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>

static void emit(const char *m) { write(1, m, strlen(m)); }

// _IOWR(0x64, nr, type) — DRM ioctl base is 'd' == 0x64.
#define DRM_IOCTL_MODE_GETRESOURCES  _IOWR(0x64, 0xa0, struct drm_mode_card_res)
#define DRM_IOCTL_MODE_GETCRTC       _IOWR(0x64, 0xa1, struct drm_mode_crtc)
#define DRM_IOCTL_MODE_GETENCODER    _IOWR(0x64, 0xa6, struct drm_mode_get_encoder)
#define DRM_IOCTL_MODE_GETCONNECTOR  _IOWR(0x64, 0xa7, struct drm_mode_get_connector)

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

struct drm_mode_get_encoder {
    uint32_t encoder_id;
    uint32_t encoder_type;
    uint32_t crtc_id;
    uint32_t possible_crtcs;
    uint32_t possible_clones;
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

#define DRM_MODE_CONNECTED 1

static int putdec(char *p, unsigned v) {
    char tmp[10]; int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    for (int i = 0; i < n; i++) p[i] = tmp[n - 1 - i];
    return n;
}

int main(void) {
    int fd = open("/dev/dri/card0", O_RDWR);
    if (fd < 0) { emit("drm_probe: FAIL open /dev/dri/card0\n"); return 1; }

    // ---- 1. GETRESOURCES pass 1: learn counts ----
    struct drm_mode_card_res res;
    memset(&res, 0, sizeof res);
    if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) {
        emit("drm_probe: FAIL GETRESOURCES pass1\n"); close(fd); return 1;
    }
    if (res.count_crtcs < 1 || res.count_connectors < 1 || res.count_encoders < 1) {
        emit("drm_probe: FAIL no crtc/connector/encoder\n"); close(fd); return 1;
    }

    // ---- GETRESOURCES pass 2: fetch ids ----
    uint32_t crtcs[16], conns[16], encs[16];
    if (res.count_crtcs > 16 || res.count_connectors > 16 || res.count_encoders > 16) {
        emit("drm_probe: FAIL too many objects\n"); close(fd); return 1;
    }
    res.crtc_id_ptr      = (uint64_t)(uintptr_t)crtcs;
    res.connector_id_ptr = (uint64_t)(uintptr_t)conns;
    res.encoder_id_ptr   = (uint64_t)(uintptr_t)encs;
    if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) {
        emit("drm_probe: FAIL GETRESOURCES pass2\n"); close(fd); return 1;
    }

    // ---- 2. GETCONNECTOR pass 1: learn mode count ----
    struct drm_mode_get_connector conn;
    memset(&conn, 0, sizeof conn);
    conn.connector_id = conns[0];
    if (ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) < 0) {
        emit("drm_probe: FAIL GETCONNECTOR pass1\n"); close(fd); return 1;
    }
    if (conn.connection != DRM_MODE_CONNECTED) {
        emit("drm_probe: FAIL connector not connected\n"); close(fd); return 1;
    }
    if (conn.count_modes < 1) {
        emit("drm_probe: FAIL no modes\n"); close(fd); return 1;
    }

    // ---- GETCONNECTOR pass 2: fetch the mode ----
    struct drm_mode_modeinfo modes[16];
    if (conn.count_modes > 16) conn.count_modes = 16;
    memset(&conn, 0, sizeof conn);
    conn.connector_id = conns[0];
    conn.count_modes  = 16;
    conn.modes_ptr    = (uint64_t)(uintptr_t)modes;
    if (ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) < 0) {
        emit("drm_probe: FAIL GETCONNECTOR pass2\n"); close(fd); return 1;
    }
    unsigned w = modes[0].hdisplay, h = modes[0].vdisplay;
    if (w < 1 || h < 1 || w > 8192 || h > 8192) {
        emit("drm_probe: FAIL insane mode dims\n"); close(fd); return 1;
    }

    // ---- 3. GETCRTC on the first crtc id ----
    struct drm_mode_crtc crtc;
    memset(&crtc, 0, sizeof crtc);
    crtc.crtc_id = crtcs[0];
    if (ioctl(fd, DRM_IOCTL_MODE_GETCRTC, &crtc) < 0) {
        emit("drm_probe: FAIL GETCRTC\n"); close(fd); return 1;
    }

    // ---- GETENCODER on the first encoder id ----
    struct drm_mode_get_encoder enc;
    memset(&enc, 0, sizeof enc);
    enc.encoder_id = encs[0];
    if (ioctl(fd, DRM_IOCTL_MODE_GETENCODER, &enc) < 0) {
        emit("drm_probe: FAIL GETENCODER\n"); close(fd); return 1;
    }
    close(fd);

    char out[80]; int p = 0;
    const char *t = "drm_probe: PASS res=";
    memcpy(out + p, t, strlen(t)); p += (int)strlen(t);
    p += putdec(out + p, w); out[p++] = 'x'; p += putdec(out + p, h);
    memcpy(out + p, " crtcs=", 7); p += 7; p += putdec(out + p, res.count_crtcs);
    memcpy(out + p, " conns=", 7); p += 7; p += putdec(out + p, res.count_connectors);
    out[p++] = '\n';
    write(1, out, p);
    return 0;
}
