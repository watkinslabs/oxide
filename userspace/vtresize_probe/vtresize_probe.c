// /bin/vtresize_probe — VT_RESIZE live-resize round-trip (console-plan B3).
//
// Regression for the real `vc_do_resize`/`fbcon_resize` reflow: VT_RESIZE must
//   1. accept a grid that FITS the fixed framebuffer scanout, reflow the VT's
//      screen buffer, and push the new tty winsize (observable via TIOCGWINSZ);
//   2. REJECT (-1/EINVAL) a grid LARGER than the native fb cell grid, and on
//      rejection NOT touch the winsize.
// /dev/tty0's TIOCGWINSZ reads the system-console winsize that VT_RESIZE's
// vt_apply_winsize updates — so the round-trip is observable from userspace.

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

#define VT_RESIZE   0x5609
#define TIOCGWINSZ_ 0x5413

struct vt_sizes { unsigned short v_rows, v_cols, v_scrollsize; };
struct winsz { unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel; };

static void emit(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int fd = open("/dev/tty0", O_RDWR);
    if (fd < 0) fd = 0;

    // Current geometry.
    struct winsz w0; memset(&w0, 0, sizeof w0);
    if (ioctl(fd, TIOCGWINSZ_, &w0) != 0 || w0.ws_row == 0 || w0.ws_col == 0) {
        emit("vtresize_probe: FAIL TIOCGWINSZ\n"); return 1;
    }

    // A size that FITS: shrink by 2 in each axis (min floor so we stay sane).
    unsigned short rows = w0.ws_row > 6 ? w0.ws_row - 2 : w0.ws_row;
    unsigned short cols = w0.ws_col > 6 ? w0.ws_col - 2 : w0.ws_col;
    struct vt_sizes fit = { rows, cols, 0 };
    if (ioctl(fd, VT_RESIZE, &fit) != 0) {
        emit("vtresize_probe: FAIL VT_RESIZE(fit)\n"); return 1;
    }
    // TIOCGWINSZ must now reflect the new grid.
    struct winsz w1; memset(&w1, 0, sizeof w1);
    if (ioctl(fd, TIOCGWINSZ_, &w1) != 0) {
        emit("vtresize_probe: FAIL TIOCGWINSZ(after fit)\n"); return 1;
    }
    if (w1.ws_row != rows || w1.ws_col != cols) {
        emit("vtresize_probe: FAIL winsize not reflected\n"); return 1;
    }

    // An ABSURD size (larger than any framebuffer scanout) must be REJECTED
    // with -1/EINVAL and must NOT change the winsize.
    struct vt_sizes big = { 9999, 9999, 0 };
    errno = 0;
    if (ioctl(fd, VT_RESIZE, &big) != -1 || errno != EINVAL) {
        emit("vtresize_probe: FAIL oversize not rejected\n"); return 1;
    }
    struct winsz w2; memset(&w2, 0, sizeof w2);
    if (ioctl(fd, TIOCGWINSZ_, &w2) != 0) {
        emit("vtresize_probe: FAIL TIOCGWINSZ(after big)\n"); return 1;
    }
    if (w2.ws_row != rows || w2.ws_col != cols) {
        emit("vtresize_probe: FAIL winsize changed on rejected resize\n"); return 1;
    }

    // Restore the original geometry (best effort).
    struct vt_sizes orig = { w0.ws_row, w0.ws_col, 0 };
    ioctl(fd, VT_RESIZE, &orig);

    emit("vtresize_probe: PASS\n");
    return 0;
}
