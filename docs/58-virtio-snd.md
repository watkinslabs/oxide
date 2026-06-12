# 58 virtio-snd (audio)

FROZEN 2026-06-12. Dep:`01`,`02`,`07`,`15`,`16`,`18`,`19`,`22`,`34`,`35`,`50`. Provides:`drv-virtio-snd`,ALSA `/dev/snd/*`,OSS `/dev/dsp`,`50` (KIOCSOUND/KDMKTONE backend).

Full Linux compat surface per virtio 1.2 §5.14 + `linux/include/uapi/sound/asound.h` (ALSA) + `linux/include/uapi/linux/soundcard.h` (OSS). No deferrals.

## 1 Purpose

Driver crate `drv-virtio-snd` for virtio device class 25 ("sound device", PCI modern device-id `0x1059`) per virtio 1.2 §5.14. Owns the wire protocol, the CONTROLQ/EVENTQ/TXQ/RXQ ring service, and the kernel-side PCM substream delivery. Consumed by userspace via the ALSA character devices under `/dev/snd/` (primary, full Linux surface) and the OSS `/dev/dsp` compat node (legacy `write(2)`-to-play). Also the audible backend for `50` (VT) `KIOCSOUND`/`KDMKTONE` when no PC-speaker port is present.

## 2 Invariants (frozen)

1. Driver lives in `crates/drivers/drv-virtio-snd`. Kernel does not link it directly; `drv::probe_all` invokes `probe(bdf)`. Pure MMIO (notify/common-cfg windows) + HHDM (rings + period buffers); zero arch-specific asm — identical on x86_64 + aarch64.
2. Four virtqueues, fixed index: CONTROLQ(0, request/response control), EVENTQ(1, device→driver notifications), TXQ(2, guest→device PCM frames for OUTPUT streams), RXQ(3, device→guest PCM frames for INPUT streams).
3. Negotiated features (v1): `VIRTIO_F_VERSION_1`(32). `VIRTIO_SND_F_CTLS`(0) negotiated when the device offers it (exposes the ALSA control/mixer element set); absent → `controls=0` and `/dev/snd/controlC0` exposes only the static master element.
4. Config space `virtio_snd_config` (16 bytes): `le32 jacks; le32 streams; le32 chmaps; le32 controls`. Read once at probe to size the PCM/jack/chmap/control tables.
5. One virtio-snd PCI function = one ALSA card `C0` (next free card index). Each PCM stream → one substream of `/dev/snd/pcmC0D<n><p|c>`; `direction=OUTPUT` → playback (`p`), `INPUT` → capture (`c`).
6. Every CONTROLQ request is `hdr.code`-tagged (`virtio_snd_hdr`); the device replies with a `virtio_snd_hdr` status (`VIRTIO_SND_S_*`) in a device-writable descriptor. The driver blocks the issuing task on a per-device `WaitQueue` until the used ring retires the request.
7. PCM I/O messages carry a leading `virtio_snd_pcm_xfer{le32 stream_id}` header, then the raw PCM payload (TX) / empty buffer (RX), then a trailing device-writable `virtio_snd_pcm_status{le32 status; le32 latency_bytes}`. One message = one period.
8. Sample formats / rates are the virtio enum on the wire, translated 1:1 to/from the ALSA `SNDRV_PCM_FORMAT_*` / explicit Hz at the device-node boundary. No format conversion in-kernel beyond this enum map (a hardware-params mismatch the device rejects → `EINVAL`, exactly as ALSA).

## 3 Public ifc

```rust
// crates/drivers/drv-virtio-snd/src/lib.rs
pub fn register();   // drv::register(DriverEntry { name: "virtio-snd", probe })

// Probe-time install hook (called from pci_boot::virtio_drv after DRIVER_OK):
pub fn install(cfg: SndInstall) -> bool;

// ALSA + OSS node backends (crates/kernel/sound consumes these):
pub fn card_count() -> u32;
pub fn pcm_info(card: u32, dev: u32, dir: Dir) -> Option<PcmInfo>;
pub fn pcm_open(card: u32, dev: u32, sub: u32, dir: Dir) -> KResult<StreamId>;
pub fn pcm_set_params(s: StreamId, p: &HwParams) -> KResult<()>;
pub fn pcm_prepare(s: StreamId) -> KResult<()>;
pub fn pcm_start(s: StreamId) -> KResult<()>;
pub fn pcm_stop(s: StreamId) -> KResult<()>;
pub fn pcm_release(s: StreamId) -> KResult<()>;
pub fn pcm_write(s: StreamId, frames: &[u8]) -> KResult<usize>;   // OUTPUT: enqueue period(s)
pub fn pcm_read(s: StreamId, frames: &mut [u8]) -> KResult<usize>; // INPUT: dequeue period(s)
pub fn pcm_avail(s: StreamId) -> usize;     // free (playback) / filled (capture) frames
pub fn pcm_hw_ptr(s: StreamId) -> u64;      // device-consumed frame counter (for SNDRV_PCM_IOCTL_HWSYNC)

// 50 (VT) tone backend:
pub fn beep(hz: u32, ms: u32) -> KResult<()>;  // synth square wave on a reserved OUTPUT stream
```

## 4 Wire structs (per virtio 1.2 §5.14)

```c
struct virtio_snd_config {            // device config space (16 bytes)
    le32 jacks; le32 streams; le32 chmaps; le32 controls;
};

struct virtio_snd_hdr      { le32 code; };          // every ctrl req/resp + event
struct virtio_snd_query_info {                       // *_INFO request
    struct virtio_snd_hdr hdr; le32 start_id; le32 count; le32 size;
};
struct virtio_snd_info     { le32 hda_fn_nid; };     // common info-element prefix

struct virtio_snd_pcm_hdr  { struct virtio_snd_hdr hdr; le32 stream_id; };

struct virtio_snd_pcm_info {
    struct virtio_snd_info hdr;
    le32 features;           // bitmask of VIRTIO_SND_PCM_F_*
    le64 formats;            // bitmask of VIRTIO_SND_PCM_FMT_*
    le64 rates;              // bitmask of VIRTIO_SND_PCM_RATE_*
    u8 direction;            // VIRTIO_SND_D_OUTPUT(0) / D_INPUT(1)
    u8 channels_min; u8 channels_max; u8 padding[5];
};

struct virtio_snd_pcm_set_params {
    struct virtio_snd_pcm_hdr hdr;
    le32 buffer_bytes; le32 period_bytes; le32 features;
    u8 channels; u8 format; u8 rate; u8 padding;
};

struct virtio_snd_pcm_xfer   { le32 stream_id; };    // leads each TXQ/RXQ message
struct virtio_snd_pcm_status { le32 status; le32 latency_bytes; }; // trails it

struct virtio_snd_jack_info  { struct virtio_snd_info hdr; le32 features; le32 hda_reg_defconf; le32 hda_reg_caps; u8 connected; u8 padding[7]; };
struct virtio_snd_chmap_info { struct virtio_snd_info hdr; u8 direction; u8 channels; u8 positions[18]; };

struct virtio_snd_event      { struct virtio_snd_hdr hdr; le32 data; }; // EVENTQ
```

### 4.1 Control codes (`hdr.code`)

| Code | Value | Dir | Meaning |
|---|---|---|---|
| `VIRTIO_SND_R_JACK_INFO` | 1 | ctrl | query jack table |
| `VIRTIO_SND_R_JACK_REMAP` | 2 | ctrl | remap jack |
| `VIRTIO_SND_R_PCM_INFO` | 0x0100 | ctrl | query PCM stream table |
| `VIRTIO_SND_R_PCM_SET_PARAMS` | 0x0101 | ctrl | set hw params on a stream |
| `VIRTIO_SND_R_PCM_PREPARE` | 0x0102 | ctrl | allocate device buffer, ready stream |
| `VIRTIO_SND_R_PCM_RELEASE` | 0x0103 | ctrl | free device buffer |
| `VIRTIO_SND_R_PCM_START` | 0x0104 | ctrl | begin streaming |
| `VIRTIO_SND_R_PCM_STOP` | 0x0105 | ctrl | pause streaming |
| `VIRTIO_SND_R_CHMAP_INFO` | 0x0200 | ctrl | query channel maps |
| `VIRTIO_SND_R_CTL_INFO` | 0x0300 | ctrl | query control (mixer) elements |
| `VIRTIO_SND_R_CTL_ENUM_ITEMS` | 0x0301 | ctrl | enum-control item names |
| `VIRTIO_SND_R_CTL_READ` | 0x0302 | ctrl | read control value |
| `VIRTIO_SND_R_CTL_WRITE` | 0x0303 | ctrl | write control value |
| `VIRTIO_SND_R_CTL_TLV_READ` | 0x0304 | ctrl | read dB-scale TLV |
| `VIRTIO_SND_R_CTL_TLV_WRITE`| 0x0305 | ctrl | write TLV |
| `VIRTIO_SND_R_CTL_TLV_COMMAND`|0x0306| ctrl | TLV command |
| `VIRTIO_SND_EVT_JACK_CONNECTED` | 0x1000 | event | jack plugged |
| `VIRTIO_SND_EVT_JACK_DISCONNECTED`|0x1001| event | jack unplugged |
| `VIRTIO_SND_EVT_PCM_PERIOD_ELAPSED`|0x1100| event | one period consumed |
| `VIRTIO_SND_EVT_PCM_XRUN` | 0x1101 | event | under/overrun |
| `VIRTIO_SND_EVT_CTL_NOTIFY`| 0x1200 | event | control value changed |

### 4.2 Status codes

| Status | Value | → errno |
|---|---|---|
| `VIRTIO_SND_S_OK` | 0x8000 | 0 |
| `VIRTIO_SND_S_BAD_MSG` | 0x8001 | `EINVAL` |
| `VIRTIO_SND_S_NOT_SUPP` | 0x8002 | `ENOTSUPP` |
| `VIRTIO_SND_S_IO_ERR` | 0x8003 | `EIO` |

### 4.3 Format + rate enums

`VIRTIO_SND_PCM_FMT_*` (`u8 format` / `le64 formats` bit): `IMA_ADPCM`=0, `MU_LAW`=1, `A_LAW`=2, `S8`=3, `U8`=4, `S16`=5, `U16`=6, `S18_3`=7, `U18_3`=8, `S20_3`=9, `U20_3`=10, `S24_3`=11, `U24_3`=12, `S20`=13, `U20`=14, `S24`=15, `U24`=16, `S32`=17, `U32`=18, `FLOAT`=19, `FLOAT64`=20, plus DSD/IEC958 (21..25).

`VIRTIO_SND_PCM_RATE_*` (`u8 rate` / `le64 rates` bit): `5512`=0, `8000`=1, `11025`=2, `16000`=3, `22050`=4, `32000`=5, `44100`=6, `48000`=7, `64000`=8, `88200`=9, `96000`=10, `176400`=11, `192000`=12, `384000`=13.

`VIRTIO_SND_D_OUTPUT`=0, `VIRTIO_SND_D_INPUT`=1. `VIRTIO_SND_PCM_F_*` features: `SHMEM_HOST`=0, `SHMEM_GUEST`=1, `MSG_POLLING`=2, `EVT_SHMEM_PERIODS`=3, `EVT_XRUNS`=4.

## 5 ALSA device nodes (`/dev/snd/`) — primary surface

Per `linux/sound/core`. Major 116 (`SNDRV_MAJOR`). Created by the `sound` kernel glue (`crates/kernel/sound`) when `card_count()>0`.

| Node | Minor | Backed by | UAPI |
|---|---|---|---|
| `/dev/snd/controlC0` | `card*32 + 0` | control element table | `SNDRV_CTL_IOCTL_*` |
| `/dev/snd/pcmC0D0p` | `card*32 + 16 + dev*2` | OUTPUT substream | `SNDRV_PCM_IOCTL_*` |
| `/dev/snd/pcmC0D0c` | `card*32 + 16 + dev*2 + 1` | INPUT substream | `SNDRV_PCM_IOCTL_*` |
| `/dev/snd/timerC0` | per `SNDRV_MINOR_TIMER` | period timer | `SNDRV_TIMER_IOCTL_*` |

### 5.1 PCM ioctls (per `sound/asound.h`, ABI `SNDRV_PCM_VERSION` 2.0.x)

| ioctl | Behavior |
|---|---|
| `SNDRV_PCM_IOCTL_PVERSION` | return protocol version |
| `SNDRV_PCM_IOCTL_INFO` | `snd_pcm_info` (card/device/subdevice/name/dir) |
| `SNDRV_PCM_IOCTL_HW_REFINE` | intersect `snd_pcm_hw_params` mask/interval against device `formats`/`rates`/`channels` |
| `SNDRV_PCM_IOCTL_HW_PARAMS` | commit params → `VIRTIO_SND_R_PCM_SET_PARAMS` |
| `SNDRV_PCM_IOCTL_SW_PARAMS` | store `avail_min`/`start_threshold` (software side; honored by poll) |
| `SNDRV_PCM_IOCTL_PREPARE` | `VIRTIO_SND_R_PCM_PREPARE` |
| `SNDRV_PCM_IOCTL_START` | `VIRTIO_SND_R_PCM_START` |
| `SNDRV_PCM_IOCTL_DROP` | `VIRTIO_SND_R_PCM_STOP` |
| `SNDRV_PCM_IOCTL_DRAIN` | block until all queued periods consumed, then STOP |
| `SNDRV_PCM_IOCTL_PAUSE` | STOP (resume = START) |
| `SNDRV_PCM_IOCTL_HWSYNC` | sync `hw_ptr` from used-ring progress |
| `SNDRV_PCM_IOCTL_SYNC_PTR` | return `snd_pcm_sync_ptr` (hw_ptr + appl_ptr + avail) |
| `SNDRV_PCM_IOCTL_STATUS` | `snd_pcm_status` (state/hw_ptr/appl_ptr/avail/delay) |
| `SNDRV_PCM_IOCTL_WRITEI_FRAMES` | interleaved playback → `pcm_write` |
| `SNDRV_PCM_IOCTL_READI_FRAMES` | interleaved capture → `pcm_read` |
| `SNDRV_PCM_IOCTL_RESET` | reset appl/hw ptrs |
| `SNDRV_PCM_IOCTL_XRUN` | force XRUN state |

`read(2)`/`write(2)` on the fd are the byte-stream equivalents of `READI/WRITEI`. `poll(2)` returns `POLLOUT` (playback: `avail >= avail_min`) / `POLLIN` (capture). `mmap(2)` of the substream exposes the period ring + control/status pages (`SNDRV_PCM_MMAP_OFFSET_*`) per the ALSA mmap ABI.

### 5.2 Control ioctls

`SNDRV_CTL_IOCTL_CARD_INFO`, `_PVERSION`, `_ELEM_LIST`, `_ELEM_INFO`, `_ELEM_READ`, `_ELEM_WRITE`, `_TLV_READ/WRITE/COMMAND`, `_SUBSCRIBE_EVENTS` — backed by the `VIRTIO_SND_R_CTL_*` element table (or the static master volume/switch when `VIRTIO_SND_F_CTLS` absent).

## 6 OSS compat node (`/dev/dsp`, `/dev/mixer`, `/dev/audio`) — legacy surface

Per `linux/include/uapi/linux/soundcard.h`. Major 14. `write(2)` of PCM → `pcm_write` on a lazily-opened OUTPUT stream; `read(2)` → capture. ioctls: `SNDCTL_DSP_SPEED` (rate), `_SETFMT` (`AFMT_S16_LE` etc. → format enum), `_CHANNELS`, `_GETBLKSIZE`, `_GETOSPACE`/`_GETISPACE`, `_SYNC`, `_RESET`, `_POST`. `/dev/audio` defaults to 8 kHz µ-law (`AFMT_MU_LAW`). `/dev/mixer` → `SOUND_MIXER_*` mapped onto the ALSA master element. OSS and ALSA nodes share the same underlying virtio streams; concurrent open of a busy stream → `EBUSY`.

## 7 Probe + bring-up

1. `drv::probe_all(bdf)` → `drv-virtio-snd::probe`. PCI match `0x1AF4`/`0x1059`.
2. Standard virtio init (ACK → DRIVER → features (`VERSION_1` + `CTLS` if offered) → FEATURES_OK).
3. Program all four queues' desc/avail/used PAs; DRIVER_OK.
4. Read `virtio_snd_config` → `streams`, `jacks`, `chmaps`, `controls`.
5. `VIRTIO_SND_R_PCM_INFO` (start_id=0, count=streams) → build the substream table (dir/formats/rates/channels per stream).
6. `VIRTIO_SND_R_CHMAP_INFO`, `VIRTIO_SND_R_JACK_INFO`, `VIRTIO_SND_R_CTL_INFO` (when present) → populate the card's chmap/jack/control tables.
7. Pre-fill EVENTQ with `virtio_snd_event` descriptors; install MSI-X/softirq drain.
8. Register ALSA card `C0`: `/dev/snd/controlC0`, one `pcmC0D<n>{p,c}` per stream, `timerC0`; register the OSS `/dev/dsp`,`/dev/mixer`,`/dev/audio` compat nodes.
9. Boot line: `virtio-snd: bdf=0:N.0 card=C0 streams=<s> out=<no> in=<ni>`.

## 8 PCM data path

- **Playback (OUTPUT/TXQ):** `pcm_write` copies the application bytes into the next free period buffer (HHDM frame), pushes a 3-descriptor chain (`xfer` hdr RO, payload RO, `status` WO) onto TXQ, advances avail, notifies. The used ring retiring the chain frees the period and bumps `hw_ptr`. `EVT_PCM_PERIOD_ELAPSED` (or used-ring progress) wakes `POLLOUT` waiters.
- **Capture (INPUT/RXQ):** the driver keeps RXQ pre-filled with empty period buffers; the device writes PCM + a trailing `status`. `pcm_read` copies out the filled prefix and re-supplies the descriptor.
- **Buffer geometry:** `buffer_bytes`/`period_bytes` from `HW_PARAMS`; period buffers are page-aligned HHDM frames, count = `buffer_bytes/period_bytes` (clamped to queue size). XRUN when the app fails to refill before the device drains (playback) or fails to drain before the device fills (capture) → `EVT_PCM_XRUN` → ALSA `SNDRV_PCM_STATE_XRUN`.

## 9 Concurrency

- CONTROLQ requests serialized by a per-device `Spinlock`; issuing task sleeps on a `WaitQueue` until the response retires.
- TXQ/RXQ drained on the device's MSI-X handler (`crate::msi`) → softirq; per-substream `WaitQueue` for blocking `read`/`write`/`poll`/`DRAIN`.
- A substream is single-open (Linux ALSA default; no `SNDRV_PCM_INFO_DOUBLE`): second open → `EBUSY`.
- `beep()` reserves substream 0's tail; refuses (`EBUSY`) if userspace holds it.

## 10 Failure modes

- No virtio-snd device: `card_count()==0`, `/dev/snd` + `/dev/dsp` absent (ENXIO on open of a hardcoded path).
- `SET_PARAMS` rejected (`S_BAD_MSG`/`S_NOT_SUPP`): `HW_PARAMS` → `EINVAL`.
- TXQ stall (device stops retiring): blocking write parks; `DRAIN` times out → `EIO`; XRUN event → state XRUN, `write` returns `EPIPE` until `PREPARE`.
- Period buffer exhaustion: `pcm_write` returns short count / `EAGAIN` on `O_NONBLOCK`.

## 11 Test contract (frozen)

- Probe smoke: `-device virtio-sound-pci,audiodev=snd0 -audiodev wav,id=snd0,path=out.wav`; driver reaches DRIVER_OK, `PCM_INFO` returns ≥1 OUTPUT stream, boot line printed.
- Hosted wire test: encode each control request, assert byte layout matches the §4 C structs; decode a canned `virtio_snd_pcm_info` blob, assert dir/formats/rates parse.
- Tone smoke: `beep(440, 200)` (or userspace writes a 440 Hz S16_LE sine to `/dev/dsp`); QEMU `wav` backend writes `out.wav`; harness asserts the file is non-empty and contains non-zero PCM samples at ≈440 Hz.
- ALSA smoke: `aplay`-style open `/dev/snd/pcmC0D0p` → `HW_PARAMS`(S16_LE/48000/2) → `PREPARE` → `WRITEI` → `DRAIN`; `SNDRV_PCM_IOCTL_STATUS` shows `hw_ptr` advancing.
- Both arches: `make qemu-x86` AND `make qemu-arm` reach login with the boot line present.
- Coverage ≥75%.

## 12 Cross-spec

`34` (PCI discovery), `35` (driver-model trait), `15§5` (read/write/poll/mmap/ioctl on the fds), `18` (devfs node registration), `50§16` (tone backend), `19` (`/proc/asound/*` + `/sys/class/sound/*` presence).

## 13 procfs + sysfs presence

`/proc/asound/cards` (card list), `/proc/asound/devices` (minor map), `/proc/asound/card0/pcm0p/info`, `/sys/class/sound/{controlC0,pcmC0D0p,...}` symlinks per Linux `sound/core/info.c` + `sound/core/sound.c`. Read-only; sourced from the card tables built at probe.
