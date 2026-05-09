# 46 virtio-input

FROZEN 2026-05-09. Dep:`01`,`02`,`07`,`13`,`15`,`22`,`34`,`35`,`50`. Provides:`drv-virtio-input`,`50` (VT keyboard backend),evdev `/dev/input/event*`.

Full Linux compat surface per `linux/include/uapi/linux/input.h` + `input-event-codes.h` + virtio 1.2 §5.8. No deferrals.

## 1 Purpose

Driver crate `drv-virtio-input` for virtio device class 18 ("input device") per virtio 1.2 §5.8. Owns the wire protocol, the EVENTQ/STATUSQ ring service, and the kernel-side evdev event delivery. Consumed by `50` (VT) for keyboard input and by userspace evdev clients via `/dev/input/event<N>`.

## 2 Invariants (frozen)

1. Driver lives in `crates/drv-virtio-input`. Kernel does not link it directly; `drv::probe_all` invokes `probe(bdf)`.
2. Two virtqueues: EVENTQ (idx=0, 64 entries, host→guest event delivery), STATUSQ (idx=1, 64 entries, guest→host status delivery e.g. LED state).
3. Negotiated features (v1): `VIRTIO_F_VERSION_1` (32) only. No device-class-specific feature bits.
4. Each virtio-input PCI function corresponds to ONE evdev `/dev/input/event<N>`. Multiple devices (kbd + mouse + tablet) = multiple PCI functions = multiple eventfds.
5. The host keeps EVENTQ filled with empty `virtio_input_event` descriptors; on input the host writes one event per descriptor and signals via the queue's `used` ring. The driver re-supplies drained descriptors.
6. `virtio_input_event` is 8 bytes (`type:le16, code:le16, value:le32`) — exactly matches Linux's `struct input_event` payload (without the timestamp; v1 stamps locally on dequeue).
7. The driver bridges to Linux's evdev `input_event` ABI per `linux/include/uapi/linux/input.h`; userspace reads of `/dev/input/event<N>` return `input_event` records with kernel-supplied timestamps.
8. Configuration space (`virtio_input_config`) is 256 bytes; the driver reads device identity (`select=ID_NAME`, `ID_SERIAL`, `ID_DEVIDS`) and capability bitmaps (`select=PROP_BITS`, `EV_BITS`, `ABS_INFO`) at probe.

## 3 Public ifc

```rust
// crates/drv-virtio-input/src/lib.rs
pub fn register();   // calls drv::register(DriverEntry { name: "virtio-input", probe })

pub struct VirtioInputDev { /* eventq/statusq refs + name + caps */ }

// 50 (VT) consumes:
pub fn poll_event(dev_id: u32) -> Option<InputEvent>;   // non-blocking
pub fn wait_event(dev_id: u32) -> InputEvent;           // blocks via WaitQueue
pub fn enumerate() -> Vec<(u32, &'static str)>;          // (dev_id, friendly_name)

// 50 + userspace evdev:
pub fn cap_ev_bits(dev_id: u32) -> [u8; 32];   // EV_KEY / EV_REL / EV_ABS / EV_SYN bits
pub fn cap_key_bits(dev_id: u32) -> [u8; 96];  // KEY_* bits per Linux 768-key range
pub fn cap_abs_info(dev_id: u32, axis: u8) -> Option<AbsInfo>;
pub fn set_led(dev_id: u32, led: u8, on: bool) -> KResult<()>;  // STATUSQ → host
```

## 4 Wire structs (per virtio 1.2 §5.8.6)

```c
struct virtio_input_event {
    le16 type;       // EV_SYN(0) / EV_KEY(1) / EV_REL(2) / EV_ABS(3) / EV_MSC(4) / EV_LED(17)
    le16 code;       // KEY_A=30, KEY_ENTER=28, REL_X=0, ABS_X=0, etc.
    le32 value;      // 0=release, 1=press, 2=autorepeat for EV_KEY; signed delta for EV_REL
};

struct virtio_input_absinfo {
    le32 min, max, fuzz, flat, res;
};
struct virtio_input_devids {
    le16 bustype, vendor, product, version;
};

struct virtio_input_config {
    u8 select;        // VIRTIO_INPUT_CFG_*
    u8 subsel;        // EV_KEY / EV_REL / etc. for *_BITS selectors
    u8 size;          // length of `u` valid bytes
    u8 reserved[5];
    union {
        char string[128];                    // ID_NAME / ID_SERIAL
        u8 bitmap[128];                      // *_BITS
        struct virtio_input_absinfo abs;     // ABS_INFO
        struct virtio_input_devids ids;      // ID_DEVIDS
    } u;
};
```

## 5 Config-space selectors

| `select` | Meaning |
|---|---|
| `VIRTIO_INPUT_CFG_UNSET` (0) | release config space |
| `VIRTIO_INPUT_CFG_ID_NAME` (1) | device name string |
| `VIRTIO_INPUT_CFG_ID_SERIAL` (2) | serial string |
| `VIRTIO_INPUT_CFG_ID_DEVIDS` (3) | bus/vendor/product/version |
| `VIRTIO_INPUT_CFG_PROP_BITS` (0x10) | property bits |
| `VIRTIO_INPUT_CFG_EV_BITS` (0x11) | EV_* type bitmap (subsel = type) |
| `VIRTIO_INPUT_CFG_ABS_INFO` (0x12) | absinfo for ABS axis (subsel = axis) |

## 6 Linux evdev mapping

Driver pushes one `virtio_input_event` per host-side input. Userspace reads `/dev/input/event<N>` and sees Linux `input_event`:

```c
struct input_event {
    struct timeval time;       // CLOCK_MONOTONIC, kernel-stamped at dequeue
    __u16 type;
    __u16 code;
    __s32 value;
};
```

`type`/`code`/`value` pass through unchanged from `virtio_input_event`. `time` is generated kernel-side from `clock::monotonic_ns` at the moment the eventq drain runs.

EV_SYN frames (`type=0, code=SYN_REPORT(0), value=0`) terminate each event group exactly as in real Linux. The driver inserts `SYN_REPORT` after each batch of host events drained from one used-ring entry.

## 7 ioctl set on `/dev/input/event<N>` (per docs/35 R01 evdev surface)

| ioctl | Code | Behavior |
|---|---|---|
| `EVIOCGVERSION` | `0x80044501` | returns `0x010001` (kernel input ABI v1.0.1) |
| `EVIOCGID` | `0x80084502` | bus/vendor/product/version from `ID_DEVIDS` |
| `EVIOCGNAME(len)` | `_IOR('E', 0x06, len)` | name string from `ID_NAME` |
| `EVIOCGUNIQ(len)` | `_IOR('E', 0x08, len)` | serial from `ID_SERIAL`; ENOENT if empty |
| `EVIOCGBIT(ev, len)` | `_IOR('E', 0x20+ev, len)` | EV_BITS for given EV type |
| `EVIOCGABS(axis)` | `_IOR('E', 0x40+axis, struct input_absinfo)` | ABS_INFO |
| `EVIOCGKEY(len)` | `_IOR('E', 0x18, len)` | snapshot of currently-pressed keys |
| `EVIOCGLED(len)` | `_IOR('E', 0x19, len)` | LED state bitmap |
| `EVIOCSREP` | `_IOW('E', 0x03, int[2])` | autorepeat delay+rate (v1: stored, no enforcement) |
| `EVIOCGRAB` | `_IOW('E', 0x90, int)` | exclusive grab; v1: tracks owner fd, returns EBUSY if already grabbed |

## 8 Probe + bring-up

1. `drv::probe_all(bdf)` enters `drv-virtio-input::probe`.
2. PCI match: `0x1AF4`/`0x1052` (modern virtio-input) only.
3. Standard virtio init (ACK → DRIVER → features → FEATURES_OK → DRIVER_OK).
4. Read config space at `select=ID_NAME` to capture friendly name.
5. Read `ID_DEVIDS` for bus/vendor/product/version (used by EVIOCGID).
6. Read `EV_BITS` (subsel=0) to learn supported event types; for each set bit, read `EV_BITS` again with subsel=that-type to learn supported codes.
7. For each supported `ABS_*` axis, read `ABS_INFO`.
8. Allocate evdev id (next free `0..N`), register `/dev/input/event<N>` Inode in devfs.
9. Pre-fill EVENTQ with 64 empty `virtio_input_event` descriptors.
10. Boot line: `virtio-input: bdf=0:N.0 evdev=/dev/input/event<N> name="<friendly>"`.

## 9 Concurrency

- EVENTQ drain runs on the receiving CPU's MSI-X handler (allocated via `crate::msi`).
- Per-device read-side `WaitQueue` for `wait_event` / blocking `read(/dev/input/event<N>)`.
- Multiple readers of the same event<N> see a SHARED stream (not a copy each); first-come-first-served. Linux behaviour.
- `EVIOCGRAB` makes the grabbing fd the only reader until close or `EVIOCGRAB(0)`.

## 10 Failure modes

- EVENTQ stall (host stops delivering): no event for >5s; driver logs `virtio-input: eventq stall device=<N>` once, no recovery action.
- STATUSQ rejection (LED set fails): propagate `EIO` to caller.
- Grab while already grabbed: `EBUSY`.
- Read on un-grabbed fd while another fd is grabber: `EAGAIN` (or block until ungrabbed).

## 11 Test contract (frozen)

- Probe smoke: at least one virtio-input device present, advances to DRIVER_OK, EV_BITS readable.
- Keystroke smoke: QEMU `-device virtio-keyboard-pci`; harness sends `qemu-monitor "sendkey a"`; userspace reading `/dev/input/event0` sees `(EV_KEY, KEY_A, 1)` then `(EV_SYN, SYN_REPORT, 0)`.
- Mouse smoke: `-device virtio-mouse-pci`; QEMU monitor `mouse_move 10 5`; reader sees `(EV_REL, REL_X, 10), (EV_REL, REL_Y, 5), (EV_SYN, SYN_REPORT, 0)`.
- EVIOCGNAME smoke: reader retrieves device name matching what `virsh domif-getlink` shows for the host.
- Coverage ≥75%.

## 12 Cross-spec

`34` (PCI host bridge for device discovery), `35` (driver-model trait), `50` (VT keyboard input consumer), `15§5` (poll(2)/read(2) on event fds).

## 13 Tablet + touchscreen + multi-touch

ABS-axis devices (tablets, touchscreens) report ABS_X / ABS_Y / ABS_PRESSURE per `linux/Documentation/input/event-codes.rst`. Full ABS_INFO (min/max/fuzz/flat/res) read from config-space and forwarded via `EVIOCGABS`.

Multi-touch via the Linux MT-B protocol (slotted) per `linux/Documentation/input/multi-touch-protocol.rst`:

| Code | Meaning |
|---|---|
| `ABS_MT_SLOT` (0x2f) | active slot id |
| `ABS_MT_TRACKING_ID` (0x39) | per-touch tracking id; `-1` = release |
| `ABS_MT_POSITION_X` / `_Y` | per-touch position |
| `ABS_MT_PRESSURE` | per-touch pressure |
| `ABS_MT_TOUCH_MAJOR` / `_MINOR` | contact area axes |
| `ABS_MT_ORIENTATION` | contact rotation |
| `BTN_TOUCH` | aggregate "any contact present" flag |

`SYN_REPORT` terminates each multi-touch frame; `SYN_MT_REPORT` legacy MT-A code accepted but driver always emits MT-B.

## 14 Force feedback (EV_FF)

When the device exposes `EV_FF` in its capability bitmap, `EVIOCSFF` uploads an effect, `EVIOCRMFF` removes it, and writes to the fd of `(EV_FF, effect_id, value)` start/stop playback. Effect types per `linux/include/uapi/linux/input.h`: `FF_RUMBLE`, `FF_PERIODIC` (sine/triangle/sawtooth/square), `FF_CONSTANT`, `FF_SPRING`, `FF_FRICTION`, `FF_DAMPER`, `FF_INERTIA`, `FF_RAMP`. Driver round-trips these to the host via STATUSQ.

## 15 Autorepeat

`EVIOCSREP` accepts `int[2] = [delay_ms, period_ms]`. Driver enforces the schedule kernel-side: when an `EV_KEY` press is received and not released for `delay_ms`, the driver injects synthetic `(EV_KEY, code, 2)` events at `period_ms` intervals into the read-side stream.

## 16 LEDs

Caps Lock / Num Lock / Scroll Lock LED state lives on the device. `EVIOCGLED` reads the bitmap; the VT layer (`50`) calls `set_led(dev_id, led, on)` which sends a STATUSQ event `(EV_LED, code, value)` to the host. Caps + Num + Scroll LED toggling driven by the matching modifier keys is handled in `50` (VT) so the kernel keymap layer owns the policy.
