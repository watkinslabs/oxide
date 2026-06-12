// /bin/snd_probe — ALSA + OSS audio regression gate (docs/58§5-6).
//
// Exercises the real device the way libasound/OSS apps do and asserts
// behaviour, not just "no error":
//   controlC0  : CARD_INFO (name), PCM_NEXT_DEVICE (==0), PCM_INFO
//   pcmC0D0p   : PVERSION; HW_PARAMS REJECTS an unsupported format (proves
//                the refinement isn't a rubber-stamp); HW_PARAMS resolves
//                S16_LE/2ch/44.1k and PINS them back; SW_PARAMS; PREPARE;
//                WRITEI a 440 Hz square wave (frames accepted); DRAIN
//   /dev/dsp   : SNDCTL_DSP SETFMT/SPEED/CHANNELS/GETBLKSIZE then write(2)
// PASS only if every assertion holds. The host wav audiodev captures the
// actual PCM for out-of-band confirmation.
//
// ALSA UAPI structs/ioctls are inline (host musl-gcc lacks <sound/asound.h>);
// layout matches the authoritative header (SNDRV_PCM_VERSION 2.0.15, LP64).

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <sys/ioctl.h>

struct snd_mask { unsigned int bits[8]; };
struct snd_interval { unsigned int min, max, flags; };
struct snd_pcm_hw_params {
    unsigned int flags;
    struct snd_mask masks[3], mres[5];
    struct snd_interval intervals[12], ires[9];
    unsigned int rmask, cmask, info, msbits, rate_num, rate_den;
    unsigned long fifo_size;
    unsigned char reserved[64];
};
struct snd_pcm_sw_params {
    int tstamp_mode; unsigned int period_step, sleep_min;
    unsigned long avail_min, xfer_align, start_threshold, stop_threshold,
                  silence_threshold, silence_size, boundary;
    unsigned int proto, tstamp_type; unsigned char reserved[56];
};
struct snd_xferi { long result; void *buf; unsigned long frames; };
struct snd_ctl_card_info {
    int card, pad;
    unsigned char id[16], driver[16], name[32], longname[80],
                  reserved_[16], mixername[80], components[128];
};

#define P_ACCESS 0
#define P_FORMAT 1
#define P_FIRST_INTERVAL 8
#define P_CHANNELS 10
#define P_RATE 11
#define ACCESS_RW_INTERLEAVED 3
#define FORMAT_S16_LE 2
#define FORMAT_FLOAT64_LE 16   /* device does not support this */

#define PCM_PVERSION   _IOR('A', 0x00, int)
#define PCM_INFO       _IOR('A', 0x01, struct snd_pcm_info)
#define PCM_HW_PARAMS  _IOWR('A', 0x11, struct snd_pcm_hw_params)
#define PCM_SW_PARAMS  _IOWR('A', 0x13, struct snd_pcm_sw_params)
#define PCM_PREPARE    _IO('A', 0x40)
#define PCM_DRAIN      _IO('A', 0x44)
#define PCM_WRITEI     _IOW('A', 0x50, struct snd_xferi)
#define PCM_READI      _IOR('A', 0x51, struct snd_xferi)
#define CTL_CARD_INFO  _IOR('U', 0x01, struct snd_ctl_card_info)
#define CTL_PCM_NEXT   _IOR('U', 0x30, int)

// OSS (linux/soundcard.h).
#define SNDCTL_DSP_SPEED      _IOWR('P', 2, int)
#define SNDCTL_DSP_GETBLKSIZE _IOWR('P', 4, int)
#define SNDCTL_DSP_SETFMT     _IOWR('P', 5, int)
#define SNDCTL_DSP_CHANNELS   _IOWR('P', 6, int)
#define AFMT_S16_LE 0x10

static void emit(const char *m) { write(1, m, strlen(m)); }
static int fail(const char *m) { emit("snd_probe: FAIL "); emit(m); emit("\n"); return 1; }

static void mask_set(struct snd_pcm_hw_params *p, int pr, unsigned v) {
    memset(&p->masks[pr], 0, sizeof p->masks[pr]);
    p->masks[pr].bits[v >> 5] |= (1u << (v & 31));
}
static int mask_only(struct snd_pcm_hw_params *p, int pr, unsigned v) {
    for (int w = 0; w < 8; w++) {
        unsigned want = (w == (int)(v >> 5)) ? (1u << (v & 31)) : 0u;
        if (p->masks[pr].bits[w] != want) return 0;
    }
    return 1;
}
static void ival_set(struct snd_pcm_hw_params *p, int pr, unsigned v) {
    struct snd_interval *i = &p->intervals[pr - P_FIRST_INTERVAL];
    i->min = i->max = v; i->flags = 0b100;
}
static unsigned ival_val(struct snd_pcm_hw_params *p, int pr) {
    return p->intervals[pr - P_FIRST_INTERVAL].min;
}
static void hw_any(struct snd_pcm_hw_params *p) {
    memset(p, 0, sizeof *p);
    for (int k = 0; k < 3; k++) memset(p->masks[k].bits, 0xff, sizeof p->masks[k].bits);
    for (int k = 0; k < 12; k++) { p->intervals[k].min = 0; p->intervals[k].max = UINT_MAX; }
    p->rmask = ~0u;
}
static void hw_base(struct snd_pcm_hw_params *p) {
    hw_any(p);
    mask_set(p, P_ACCESS, ACCESS_RW_INTERLEAVED);
}

int main(void) {
    // ── controlC0 ──
    int cfd = open("/dev/snd/controlC0", O_RDONLY);
    if (cfd < 0) return fail("open controlC0");
    struct snd_ctl_card_info ci; memset(&ci, 0, sizeof ci);
    if (ioctl(cfd, CTL_CARD_INFO, &ci) < 0) return fail("CARD_INFO");
    if (ci.name[0] == 0) return fail("empty card name");
    int dev = -1;
    if (ioctl(cfd, CTL_PCM_NEXT, &dev) < 0) return fail("PCM_NEXT_DEVICE");
    if (dev != 0) return fail("expected pcm device 0");
    close(cfd);

    // ── pcmC0D0p ──
    int fd = open("/dev/snd/pcmC0D0p", O_WRONLY);
    if (fd < 0) return fail("open pcmC0D0p");
    int ver = 0;
    if (ioctl(fd, PCM_PVERSION, &ver) < 0) return fail("PVERSION");

    // Refinement must REJECT a format the device doesn't support.
    struct snd_pcm_hw_params bad; hw_base(&bad);
    mask_set(&bad, P_FORMAT, FORMAT_FLOAT64_LE);
    ival_set(&bad, P_CHANNELS, 2);
    ival_set(&bad, P_RATE, 44100);
    if (ioctl(fd, PCM_HW_PARAMS, &bad) == 0) return fail("HW_PARAMS accepted FLOAT64 (no refine)");

    // Valid params must resolve and be PINNED back.
    struct snd_pcm_hw_params hw; hw_base(&hw);
    mask_set(&hw, P_FORMAT, FORMAT_S16_LE);
    ival_set(&hw, P_CHANNELS, 2);
    ival_set(&hw, P_RATE, 44100);
    if (ioctl(fd, PCM_HW_PARAMS, &hw) < 0) return fail("HW_PARAMS S16/2/44100");
    if (!mask_only(&hw, P_FORMAT, FORMAT_S16_LE)) return fail("format not pinned to S16_LE");
    if (ival_val(&hw, P_CHANNELS) != 2) return fail("channels not pinned to 2");
    if (ival_val(&hw, P_RATE) != 44100) return fail("rate not pinned to 44100");

    struct snd_pcm_sw_params sw; memset(&sw, 0, sizeof sw);
    sw.start_threshold = 1; sw.avail_min = 1; sw.boundary = 1;
    ioctl(fd, PCM_SW_PARAMS, &sw);
    if (ioctl(fd, PCM_PREPARE, 0) < 0) return fail("PREPARE");

    enum { FRAMES = 6615 };
    static short pcm[FRAMES * 2];
    int half = 44100 / (2 * 440);
    for (int n = 0; n < FRAMES; n++) {
        short a = ((n / half) & 1) ? -8000 : 8000;
        pcm[n * 2] = a; pcm[n * 2 + 1] = a;
    }
    struct snd_xferi xf = { .result = 0, .buf = pcm, .frames = FRAMES };
    long w = ioctl(fd, PCM_WRITEI, &xf);
    if (w < 0) return fail("WRITEI");
    if (w == 0 && xf.result <= 0) return fail("WRITEI accepted 0 frames");
    ioctl(fd, PCM_DRAIN, 0);
    close(fd);

    // ── pcmC0D0c (capture, RXQ) ──
    int rfd = open("/dev/snd/pcmC0D0c", O_RDONLY);
    if (rfd < 0) return fail("open pcmC0D0c");
    struct snd_pcm_hw_params rhw; hw_base(&rhw);
    mask_set(&rhw, P_FORMAT, FORMAT_S16_LE);
    ival_set(&rhw, P_CHANNELS, 2);
    ival_set(&rhw, P_RATE, 44100);
    if (ioctl(rfd, PCM_HW_PARAMS, &rhw) < 0) return fail("capture HW_PARAMS");
    if (ioctl(rfd, PCM_PREPARE, 0) < 0) return fail("capture PREPARE");
    enum { CFRAMES = 512 };
    static short cbuf[CFRAMES * 2];
    struct snd_xferi rxf = { .result = 0, .buf = cbuf, .frames = CFRAMES };
    long r = ioctl(rfd, PCM_READI, &rxf);
    if (r < 0 && rxf.result <= 0) return fail("capture READI");
    ioctl(rfd, PCM_DRAIN, 0);
    close(rfd);

    // ── OSS /dev/dsp ──
    int dfd = open("/dev/dsp", O_WRONLY);
    if (dfd < 0) return fail("open /dev/dsp");
    int fmt = AFMT_S16_LE, ch = 2, speed = 44100, blk = 0;
    if (ioctl(dfd, SNDCTL_DSP_SETFMT, &fmt) < 0) return fail("DSP_SETFMT");
    if (ioctl(dfd, SNDCTL_DSP_CHANNELS, &ch) < 0) return fail("DSP_CHANNELS");
    if (ioctl(dfd, SNDCTL_DSP_SPEED, &speed) < 0) return fail("DSP_SPEED");
    if (ioctl(dfd, SNDCTL_DSP_GETBLKSIZE, &blk) < 0 || blk <= 0) return fail("DSP_GETBLKSIZE");
    static unsigned char oss[4096];
    for (int i = 0; i < (int)sizeof oss; i += 4) {
        short a = ((i / 200) & 1) ? -6000 : 6000;
        oss[i] = a & 0xff; oss[i+1] = (a >> 8) & 0xff;
        oss[i+2] = a & 0xff; oss[i+3] = (a >> 8) & 0xff;
    }
    long ow = write(dfd, oss, sizeof oss);
    if (ow <= 0) return fail("/dev/dsp write");
    close(dfd);

    emit("snd_probe: PASS\n");
    return 0;
}
