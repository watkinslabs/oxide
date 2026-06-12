// /bin/mouseprobe — virtio-input pointer verifier on /dev/input/event1.
//
// Two-part gate, both the Linux way:
//  (1) evdev capability suite — query the node with the real EVIOCG* ioctls
//      (EVIOCGVERSION/EVIOCGID/EVIOCGNAME/EVIOCGPROP/EVIOCGBIT) and assert the
//      device self-describes as a pointer (advertises EV_REL or EV_ABS in its
//      EV_BITS bitmap), exactly as libinput/X11 classify input devices.
//  (2) event flow — poll for input_event records and confirm host-injected
//      motion (EV_REL/EV_ABS) + a button (EV_KEY BTN_*) + a frame (EV_SYN)
//      arrive, proving QMP input → virtio-input → evdev → userspace works.
//
// PASS requires both. Named without an underscore so the login harness can
// type it.

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <poll.h>
#include <sys/ioctl.h>

struct input_event {            // Linux input.h, LP64 — 24 bytes.
    unsigned long sec, usec;
    unsigned short type, code;
    int value;
};
struct input_id { unsigned short bustype, vendor, product, version; };

#define EV_SYN 0x00
#define EV_KEY 0x01
#define EV_REL 0x02
#define EV_ABS 0x03
#define BTN_MISC 0x100

// asm-generic/ioctl.h — encode(dir,type,nr,size); dir READ=2.
#define IOC_RD(t,n,s)   ((2U<<30)|((unsigned)(s)<<16)|((unsigned)(t)<<8)|(n))
#define EVIOCGVERSION   IOC_RD('E',0x01,4)
#define EVIOCGID        IOC_RD('E',0x02,8)
#define EVIOCGNAME(l)   IOC_RD('E',0x06,(l))
#define EVIOCGPROP(l)   IOC_RD('E',0x09,(l))
#define EVIOCGBIT(e,l)  IOC_RD('E',0x20+(e),(l))

static void emit(const char *m) { write(1, m, strlen(m)); }

static void num(char *d, int *n, const char *lbl, long v) {
    for (const char *q = lbl; *q; q++) d[(*n)++] = *q;
    d[(*n)++] = '0' + (char)(v > 9 ? 9 : (v < 0 ? 0 : v));
}

int main(void) {
    int f0 = open("/dev/input/event0", O_RDONLY | O_NONBLOCK);  // keyboard
    int f1 = open("/dev/input/event1", O_RDONLY | O_NONBLOCK);  // pointer
    if (f1 < 0) { emit("mouseprobe: FAIL open event1\n"); return 1; }

    // ---- (1) evdev capability suite -----------------------------------------
    int ver = 0; struct input_id id = {0};
    char name[128] = {0}; unsigned char evb[4] = {0}, relb[4] = {0}, prop[4] = {0};
    int rv_ver  = ioctl(f1, EVIOCGVERSION, &ver);
    int rv_id   = ioctl(f1, EVIOCGID, &id);
    int rv_name = ioctl(f1, EVIOCGNAME(sizeof name), name);
    int rv_bit  = ioctl(f1, EVIOCGBIT(0, sizeof evb), evb);
    ioctl(f1, EVIOCGBIT(EV_REL, sizeof relb), relb);
    ioctl(f1, EVIOCGPROP(sizeof prop), prop);
    int has_rel = (evb[0] >> EV_REL) & 1;
    int has_abs = (evb[0] >> EV_ABS) & 1;
    int caps_ok = rv_ver >= 0 && rv_id >= 0 && rv_name >= 0 && rv_bit >= 0
                  && ver == 0x010001 && (has_rel || has_abs);

    char cd[160]; int cn = 0;
    for (const char *q = "mouseprobe: name="; *q; q++) cd[cn++] = *q;
    for (int i = 0; name[i] && cn < 140; i++) cd[cn++] = name[i];
    num(cd, &cn, " ver=", ver == 0x010001);
    num(cd, &cn, " rel=", has_rel);
    num(cd, &cn, " abs=", has_abs);
    num(cd, &cn, " vend=", id.vendor != 0);
    cd[cn++] = '\n'; write(1, cd, cn);

    // ---- (2) event flow -----------------------------------------------------
    struct pollfd p[2] = { { f0, POLLIN, 0 }, { f1, POLLIN, 0 } };
    long ev0 = 0, ev1 = 0;
    int saw_motion = 0, saw_btn = 0, saw_syn = 0;

    for (int i = 0; i < 50; i++) {                     // ~10 s
        int r = poll(p, 2, 200);
        if (r <= 0) continue;
        struct input_event ev;
        if ((p[0].revents & POLLIN))
            while (read(f0, &ev, sizeof ev) == (long) sizeof ev) ev0++;
        if ((p[1].revents & POLLIN))
            while (read(f1, &ev, sizeof ev) == (long) sizeof ev) {
                ev1++;
                if (ev.type == EV_ABS || ev.type == EV_REL) saw_motion = 1;
                if (ev.type == EV_KEY && ev.code >= BTN_MISC) saw_btn = 1;
                if (ev.type == EV_SYN) saw_syn = 1;
            }
        if (saw_motion && saw_btn && saw_syn) break;
    }
    if (f0 >= 0) close(f0);
    close(f1);

    char d[96]; int n = 0;
    num(d, &n, "mouseprobe: ev0=", ev0);
    num(d, &n, " ev1=", ev1);
    num(d, &n, " motion=", saw_motion);
    num(d, &n, " btn=", saw_btn);
    num(d, &n, " syn=", saw_syn);
    d[n++] = '\n'; write(1, d, n);

    if (!caps_ok) { emit("mouseprobe: FAIL evdev capability suite\n"); return 1; }
    if (saw_motion && saw_btn && saw_syn) { emit("mouseprobe: PASS\n"); return 0; }
    if (!saw_motion) emit("mouseprobe: FAIL no motion\n");
    else if (!saw_btn) emit("mouseprobe: FAIL no button\n");
    else emit("mouseprobe: FAIL no syn\n");
    return 1;
}
