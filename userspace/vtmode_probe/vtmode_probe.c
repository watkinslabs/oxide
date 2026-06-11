// /bin/vtmode_probe — VT_GETMODE/SETMODE + KD*LED + VT_RESIZE ioctl glue.
//
// Regression for console-plan #6: the kernel must marshal the vt_mode struct
// (VT_GETMODE/SETMODE), the LED bits (KDSETLED/KDGETLED), and the resize
// (VT_RESIZE) faithfully. Round-trips each and checks the value survives —
// exercising the read/write_volatile struct marshalling the host tests can't.

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>

#define VT_GETMODE 0x5601
#define VT_SETMODE 0x5602
#define VT_RESIZE  0x5609
#define KDGETLED   0x4B31
#define KDSETLED   0x4B32

#define VT_PROCESS 1

struct vt_mode { unsigned char mode, waitv; unsigned short relsig, acqsig, frsig; };
struct vt_sizes { unsigned short v_rows, v_cols, v_scrollsize; };

static void emit(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int fd = open("/dev/tty0", O_RDWR);
    if (fd < 0) fd = 0;

    // VT_SETMODE → VT_GETMODE round-trip.
    struct vt_mode sm = { VT_PROCESS, 0, 10, 12, 0 };
    if (ioctl(fd, VT_SETMODE, &sm) != 0) { emit("vtmode_probe: FAIL VT_SETMODE\n"); return 1; }
    struct vt_mode gm; memset(&gm, 0, sizeof gm);
    if (ioctl(fd, VT_GETMODE, &gm) != 0) { emit("vtmode_probe: FAIL VT_GETMODE\n"); return 1; }
    if (gm.mode != VT_PROCESS || gm.relsig != 10 || gm.acqsig != 12) {
        emit("vtmode_probe: FAIL vt_mode roundtrip\n"); return 1;
    }

    // KDSETLED → KDGETLED round-trip (Scroll|Caps = 0b101).
    if (ioctl(fd, KDSETLED, 0x5) != 0) { emit("vtmode_probe: FAIL KDSETLED\n"); return 1; }
    unsigned char led = 0;
    if (ioctl(fd, KDGETLED, &led) != 0) { emit("vtmode_probe: FAIL KDGETLED\n"); return 1; }
    if (led != 0x5) { emit("vtmode_probe: FAIL led roundtrip\n"); return 1; }

    // VT_RESIZE accepted (rows/cols stored; winsize + SIGWINCH side effect).
    struct vt_sizes vs = { 50, 160, 0 };
    if (ioctl(fd, VT_RESIZE, &vs) != 0) { emit("vtmode_probe: FAIL VT_RESIZE\n"); return 1; }

    // Restore VT_AUTO so we don't leave the console in process-switch mode.
    struct vt_mode au = { 0, 0, 0, 0, 0 };
    ioctl(fd, VT_SETMODE, &au);

    emit("vtmode_probe: PASS\n");
    return 0;
}
