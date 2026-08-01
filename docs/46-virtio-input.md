# 46 virtio-input

FROZEN 2026-05-09. Dep:`01`,`02`,`07`,`13`,`15`,`22`,`34`,`35`,`50`. Provides:`drv-virtio-input`,`50` (VT keyboard backend),evdev `/dev/input/event*`.

Full evdev/input-event UAPI surface plus virtio 1.2 §5.8. No deferrals.

## 1 Purpose

Driver crate `drv-virtio-input` for virtio device class 18 ("input device") per virtio 1.2 §5.8. Owns the wire protocol, the EVENTQ/STATUSQ ring service, and the kernel-side evdev event delivery. Consumed by `50` (VT) for keyboard input and by userspace evdev clients via `/dev/input/event<N>`.

## 2 Invariants (frozen)

1. Driver lives in `crates/drivers/drv-virtio-input`. The virtio bus registers the child device and binds it through the `drv::Driver` probe/remove path.
2. Two required virtqueues: EVENTQ (idx=0, host→guest event delivery) and STATUSQ (idx=1, guest→host status delivery). EVENTQ pre-fills `min(negotiated_depth, 64)` buffers as Linux does; STATUSQ uses bounded driver-owned output buffers.
3. Negotiated features (v1): `VIRTIO_F_VERSION_1` (32) only. No device-class-specific feature bits.
4. Each virtio-input PCI function corresponds to one input device and one evdev `/dev/input/event<N>` character node. Multiple devices (keyboard + mouse + tablet) use distinct PCI functions and evdev nodes.
5. The host keeps EVENTQ filled with empty `virtio_input_event` descriptors; on input the host writes one event per descriptor and signals via the queue's `used` ring. The driver re-supplies drained descriptors.
6. `virtio_input_event` is 8 bytes (`type:le16, code:le16, value:le32`) and carries the non-time fields of Linux `struct input_event`.
7. Input core validates capabilities, updates canonical state, forms packets, and supplies monotonic/realtime/boottime timestamps selected independently by each open evdev client.
8. Configuration space (`virtio_input_config`) is 256 bytes; the driver reads device identity (`select=ID_NAME`, `ID_SERIAL`, `ID_DEVIDS`) and capability bitmaps (`select=PROP_BITS`, `EV_BITS`, `ABS_INFO`) at probe.
9. inputN identity is monotonic and retained sysfs/devfs/proc objects bind the exact registered device object; recycled event minors never make an old inode or fd alias a replacement.

## 3 Public ifc

```rust
// crates/drivers/drv-virtio-input/src/lib.rs
pub fn install_device_with_parent(
    key: VirtioChildDeviceKey,
    resources: VirtioResources,
    parent: ModelParent,
) -> Option<u32>;
pub fn remove_device_with_node(key: VirtioChildDeviceKey) -> Option<u32>;
pub fn send_status(key: VirtioChildDeviceKey, event: VirtioInputEvent) -> KResult<()>;
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
    struct timeval time;       // per-client selected clock
    __u16 type;
    __u16 code;
    __s32 value;
};
```

Input core ignores unadvertised types/codes, duplicate KEY/SW/LED state, zero REL events, and all device-origin events while inhibited. Accepted state changes become a packet only when the device supplies `EV_SYN/SYN_REPORT`; the driver neither invents nor rewrites frame boundaries. Every eligible open client receives its own copy of each completed packet.

The completed packet receives one input-core timestamp. Each client converts it to `CLOCK_REALTIME`, `CLOCK_MONOTONIC`, or `CLOCK_BOOTTIME` according to its `EVIOCSCLOCKID` state. Client-buffer overflow drops unread data and starts recovery with `EV_SYN/SYN_DROPPED`.

## 7 ioctl set on `/dev/input/event<N>` (evdev surface per `35§3`)

| ioctl | Code | Behavior |
|---|---|---|
| `EVIOCGVERSION` | `0x80044501` | returns `0x010001` (kernel input ABI v1.0.1) |
| `EVIOCGID` | `0x80084502` | bus/vendor/product/version from `ID_DEVIDS` |
| `EVIOCGNAME(len)` | `_IOR('E', 0x06, len)` | name string from `ID_NAME` |
| `EVIOCGPHYS(len)` | `_IOR('E', 0x07, len)` | `virtioN/input0` |
| `EVIOCGUNIQ(len)` | `_IOR('E', 0x08, len)` | serial string; empty virtio serial returns one NUL byte |
| `EVIOCGPROP(len)` | `_IOR('E', 0x09, len)` | input property bitmap |
| `EVIOCGBIT(ev, len)` | `_IOR('E', 0x20+ev, len)` | capability bitmap for event type |
| `EVIOCGABS(axis)` | `_IOR('E', 0x40+axis, struct input_absinfo)` | ABS_INFO |
| `EVIOCGKEY/LED/SND/SW(len)` | `_IOR('E', 0x18..0x1b, len)` | canonical state; flush same-type events only from calling client |
| `EVIOCGREP/EVIOCSREP` | `_IOR/_IOW('E', 0x03, int[2])` | read/inject input-core repeat delay and period; `ENOSYS` without EV_REP |
| `EVIOCGRAB` | `_IOW('E', 0x90, int)` | nonzero grabs exact client; zero ungrabs it; `EBUSY`/`EINVAL` match Linux |
| `EVIOCREVOKE` | `_IOW('E', 0x91, int)` | zero revokes calling client; nonzero returns `EINVAL` |
| `EVIOCSCLOCKID` | `_IOW('E', 0xa0, int)` | per-client realtime/monotonic/boottime clock |

Bitmap results use Linux native-word rounding and caller-length truncation: EV/REL/ABS/MSC/SW/LED/SND/PROP = 8 bytes, KEY = 96 bytes, FF = 16 bytes on 64-bit. State ioctls use KEY = 96 bytes and LED/SND/SW = 8 bytes. Successful state copy removes pending events of that type only from the calling client; failed copy additionally queues `SYN_DROPPED`.

## 8 Probe + bring-up

1. The virtio bus binds the virtio-input child device through `Driver::probe`.
2. PCI match: `0x1AF4`/`0x1052` (modern virtio-input) only.
3. Standard virtio init (ACK → DRIVER → features → FEATURES_OK → DRIVER_OK).
4. Read config space at `select=ID_NAME` to capture friendly name.
5. Read `ID_DEVIDS` for bus/vendor/product/version (used by EVIOCGID).
6. Read PROP_BITS; probe EV_REP; read EV_KEY/REL/ABS/MSC/SW for device→kernel input and EV_LED/SND for kernel→device output, matching Linux `virtinput_probe`.
7. For each supported `ABS_*` axis, read `ABS_INFO`.
8. Allocate evdev id (next free `0..N`), register `/dev/input/event<N>` Inode in devfs.
9. Require EVENTQ + STATUSQ, then pre-fill EVENTQ with up to 64 empty `virtio_input_event` descriptors.
10. Boot line: `virtio-input: bdf=0:N.0 evdev=/dev/input/event<N> name="<friendly>"`.

## 9 Concurrency

- EVENTQ drain runs on the receiving CPU's MSI-X handler (allocated via `crate::msi`).
- Each open file owns a client queue, waiters, clock selection, event masks, revoke state, and exact endpoint reference.
- Without a grab, every client receives every completed packet. A grab routes new packets only to its owner; other clients may drain packets already queued before the grab.
- Close detaches only that client. Device disconnect marks the endpoint dead, wakes every client, makes reads return `ENODEV`, and makes poll report `POLLHUP|POLLERR` without aliasing a recycled event minor.
- State-query queue reconciliation takes canonical-state lock before client-queue lock and never flushes another client.

## 10 Failure modes

- Missing/invalid EVENTQ or STATUSQ: probe fails and publishes no input device.
- Client queue overflow: retain `SYN_DROPPED` plus newest data so userspace resynchronizes from state ioctls.
- STATUSQ buffer exhaustion/allocation failure: drop that best-effort device status update as Linux does; evdev write still returns accepted input-event bytes.
- Grab by a second client: `EBUSY`; ungrab by a non-owner: `EINVAL`.
- Revoked or disconnected client: read/write/ioctl returns `ENODEV`; poll reports `POLLHUP|POLLERR`.

## 11 Test contract (frozen)

- Probe smoke: at least one virtio-input device present, advances to DRIVER_OK, EV_BITS readable.
- Keystroke smoke: QEMU `-device virtio-keyboard-pci`; harness sends `qemu-monitor "sendkey a"`; userspace reading `/dev/input/event0` sees `(EV_KEY, KEY_A, 1)` then `(EV_SYN, SYN_REPORT, 0)`.
- Mouse smoke: `-device virtio-mouse-pci`; QEMU monitor `mouse_move 10 5`; reader sees `(EV_REL, REL_X, 10), (EV_REL, REL_Y, 5), (EV_SYN, SYN_REPORT, 0)`.
- EVIOCGNAME smoke: reader retrieves device name matching what `virsh domif-getlink` shows for the host.
- Two-open client test: both clients receive the same packet; grab routes later packets only to owner; ungrab restores fanout.
- State reconciliation test: EVIOCGKEY/LED/SND/SW removes same-type pending events only from calling client.
- Lifetime test: disconnect wakes all clients with HUP/ERR + ENODEV; reused event minor never revives an old fd or leaks queued data.
- STATUSQ test: descriptor is driver-readable, completion frees its exact slot, exhaustion fails closed, and teardown frees event + status buffers.
- Inhibit test: release keys + SYN, send active LED/SND off, filter device input, then restore LED/SND and REP on uninhibit.
- Coverage ≥75%.

## 12 Cross-spec

`34` (PCI host bridge for device discovery), `35` (driver-model trait), `50` (VT keyboard input consumer), `15§5` (poll(2)/read(2) on event fds).

## 13 Tablet + touchscreen + multi-touch

ABS-axis devices (tablets, touchscreens) report ABS_X / ABS_Y / ABS_PRESSURE per the input-event ABI. Full ABS_INFO (min/max/fuzz/flat/res) read from config-space and forwarded via `EVIOCGABS`.

Multi-touch uses the slotted MT-B protocol:

| Code | Meaning |
|---|---|
| `ABS_MT_SLOT` (0x2f) | active slot id |
| `ABS_MT_TRACKING_ID` (0x39) | per-touch tracking id; `-1` = release |
| `ABS_MT_POSITION_X` / `_Y` | per-touch position |
| `ABS_MT_PRESSURE` | per-touch pressure |
| `ABS_MT_TOUCH_MAJOR` / `_MINOR` | contact area axes |
| `ABS_MT_ORIENTATION` | contact rotation |
| `BTN_TOUCH` | aggregate "any contact present" flag |

`SYN_REPORT` terminates each multi-touch frame. Virtio-input forwards the host protocol after input-core validation; it does not translate MT-A into MT-B.

## 14 Force feedback (EV_FF)

Virtio-input does not register a force-feedback backend. `drv-virtio-input` therefore does not advertise EV_FF even if a nonconforming host exposes those bits. Generic evdev force-feedback UAPI belongs to input core and devices that register a real FF backend.

## 15 Autorepeat

`EVIOCSREP` accepts `int[2] = [delay_ms, period_ms]` and injects `EV_REP/REP_DELAY` then `EV_REP/REP_PERIOD` through canonical input core. Input core owns the timer: an unreleased key emits `(EV_KEY, code, 2)` plus `SYN_REPORT` after the delay and at each nonzero period. STATUSQ receives the accepted EV_REP updates.

## 16 LEDs

Caps Lock / Num Lock / Scroll Lock LED state lives in canonical input core. Accepted EV_LED/EV_SND/EV_REP output is sent to the exact device through STATUSQ; duplicate LED state is suppressed. Inhibit releases pressed keys and emits `SYN_REPORT`, sends active LED/SND state off, then filters device-origin input. Uninhibit clears the filter and restores active LED/SND plus REP period then delay. Modifier policy remains in `50`.
