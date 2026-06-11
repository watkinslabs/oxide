// /bin/vtswitch_probe — VT_ACTIVATE drives the ONE unified switch.
//
// Regression for console-plan #4: VT_ACTIVATE (ioctl) and Ctrl-Alt-Fn
// (keyboard) must share a single switch path that moves the framebuffer
// view AND the keyboard input foreground AND the administrative active VT
// together. Before the unify, VT_ACTIVATE updated only the administrative
// state (display + input stayed put). This probe issues VT_ACTIVATE and
// confirms VT_GETSTATE reflects the new active VT — exercising the full
// kernel switch (fbcon repaint + tty foreground retarget) without crashing,
// in a real boot. (Visual screen+input co-switch is the interactive check.)

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>

#define VT_GETSTATE 0x5603
#define VT_ACTIVATE 0x5606

struct vt_stat { unsigned short v_active, v_signal, v_state; };

static void emit(const char *m) { write(1, m, strlen(m)); }

int main(void) {
    int fd = open("/dev/tty0", O_RDWR);
    if (fd < 0) fd = 0; // fall back to inherited /dev/console
    struct vt_stat st;

    if (ioctl(fd, VT_GETSTATE, &st) != 0) {
        emit("vtswitch_probe: FAIL VT_GETSTATE\n");
        return 1;
    }
    unsigned short orig = st.v_active;

    // Switch to VT 2, confirm the active VT followed.
    if (ioctl(fd, VT_ACTIVATE, 2) != 0) {
        emit("vtswitch_probe: FAIL VT_ACTIVATE 2\n");
        return 1;
    }
    if (ioctl(fd, VT_GETSTATE, &st) != 0 || st.v_active != 2) {
        emit("vtswitch_probe: FAIL active!=2 after VT_ACTIVATE\n");
        return 1;
    }

    // Switch back to the original VT (leave the console as we found it).
    ioctl(fd, VT_ACTIVATE, orig ? orig : 1);
    ioctl(fd, VT_GETSTATE, &st);
    if (st.v_active != (orig ? orig : 1)) {
        emit("vtswitch_probe: FAIL restore\n");
        return 1;
    }

    emit("vtswitch_probe: PASS\n");
    return 0;
}
