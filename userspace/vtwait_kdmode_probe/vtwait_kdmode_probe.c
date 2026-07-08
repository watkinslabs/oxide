// /bin/vtwait_kdmode_probe - VT_WAITACTIVE + KDSETMODE/KDGETMODE runtime probe.
//
// This covers the pre-GUI contract display managers and compositors depend on:
// a VT_ACTIVATE completion must make VT_WAITACTIVE return, and KD graphics/text
// mode must round-trip on the active console without requiring a desktop stack.

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

#define KDSETMODE     0x4B3A
#define KDGETMODE     0x4B3B
#define KD_TEXT       0x00
#define KD_GRAPHICS   0x01
#define VT_GETSTATE   0x5603
#define VT_ACTIVATE   0x5606
#define VT_WAITACTIVE 0x5607

struct vt_stat { unsigned short v_active, v_signal, v_state; };

static void emit(const char *m) { write(1, m, strlen(m)); }

static int wait_for_vt(int fd, unsigned short vt) {
    if (ioctl(fd, VT_ACTIVATE, (unsigned long)vt) != 0) return -1;
    if (ioctl(fd, VT_WAITACTIVE, (unsigned long)vt) != 0) return -1;
    return 0;
}

int main(void) {
    int fd = open("/dev/tty0", O_RDWR);
    if (fd < 0) fd = 0;

    int orig_mode = KD_TEXT;
    if (ioctl(fd, KDGETMODE, &orig_mode) != 0) {
        emit("vtwait_kdmode_probe: FAIL KDGETMODE initial\n");
        return 1;
    }
    if (ioctl(fd, KDSETMODE, KD_GRAPHICS) != 0) {
        emit("vtwait_kdmode_probe: FAIL KDSETMODE graphics\n");
        return 1;
    }
    int mode = -1;
    if (ioctl(fd, KDGETMODE, &mode) != 0 || mode != KD_GRAPHICS) {
        ioctl(fd, KDSETMODE, orig_mode);
        emit("vtwait_kdmode_probe: FAIL graphics roundtrip\n");
        return 1;
    }
    if (ioctl(fd, KDSETMODE, KD_TEXT) != 0) {
        emit("vtwait_kdmode_probe: FAIL KDSETMODE text\n");
        return 1;
    }
    mode = -1;
    if (ioctl(fd, KDGETMODE, &mode) != 0 || mode != KD_TEXT) {
        ioctl(fd, KDSETMODE, orig_mode);
        emit("vtwait_kdmode_probe: FAIL text roundtrip\n");
        return 1;
    }
    ioctl(fd, KDSETMODE, orig_mode);

    struct vt_stat st;
    memset(&st, 0, sizeof st);
    if (ioctl(fd, VT_GETSTATE, &st) != 0 || st.v_active == 0) {
        emit("vtwait_kdmode_probe: FAIL VT_GETSTATE initial\n");
        return 1;
    }
    unsigned short orig = st.v_active;
    unsigned short target = orig == 2 ? 1 : 2;

    if (wait_for_vt(fd, target) != 0) {
        emit("vtwait_kdmode_probe: FAIL wait target\n");
        return 1;
    }
    memset(&st, 0, sizeof st);
    if (ioctl(fd, VT_GETSTATE, &st) != 0 || st.v_active != target) {
        emit("vtwait_kdmode_probe: FAIL active target\n");
        return 1;
    }

    if (wait_for_vt(fd, orig) != 0) {
        emit("vtwait_kdmode_probe: FAIL restore wait\n");
        return 1;
    }
    memset(&st, 0, sizeof st);
    if (ioctl(fd, VT_GETSTATE, &st) != 0 || st.v_active != orig) {
        emit("vtwait_kdmode_probe: FAIL restore active\n");
        return 1;
    }

    errno = 0;
    if (ioctl(fd, VT_WAITACTIVE, 64UL) != -1 || errno != EINVAL) {
        emit("vtwait_kdmode_probe: FAIL invalid wait errno\n");
        return 1;
    }

    emit("vtwait_kdmode_probe: PASS\n");
    return 0;
}
