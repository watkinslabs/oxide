# Driver Linux-Compliance Ledger

Date: 2026-06-28

This is the work ledger for getting the driver stack to Linux-shaped correctness for a graphical GDM/GNOME boot. It is intentionally task-oriented: each row is something that must be implemented, removed, validated, or proven absent. "Done" means the acceptance test passes under QEMU and the exposed Linux ABI does not lie to userspace.

Legend:

- `P0`: blocks GDM/GNOME or driver correctness.
- `P1`: required for broad Linux compatibility and stress.
- `P2`: required for completeness, hotplug, or non-QEMU hardware.
- `Area`: primary files/crates to touch.
- `Done`: concrete acceptance gate.

## P0 Ledger

| ID | Area | What needs doing | Done |
|---|---|---|---|
| DVR-0001 | `crates/drivers/drv`, `crates/kernel/pci-boot` | Move actual device bring-up out of `pci-boot` inline functions and into `drv::Driver::probe` for virtio-gpu, virtio-input, virtio-blk, virtio-net, virtio-rng, virtio-vsock, virtio-snd, NVMe, and AHCI. | Boot path enumerates devices, calls real probe, stores a live driver instance, and no driver has "probe already happened" comments/no-op probe. |
| DVR-0002 | `crates/drivers/drv/src/model.rs` | Add a stored per-device `DriverInstance` with `remove()` and `shutdown()` hooks. | Each bound device has an instance handle; `poweroff/reboot` calls every `shutdown()` once. |
| DVR-0003 | `crates/drivers/drv`, `sysfs` | Implement Linux-like bind/unbind state machine. | `/sys/bus/pci/drivers/<driver>/bind` and `unbind` work for at least virtio-blk in QEMU; duplicate bind returns Linux-compatible error. |
| DVR-0004 | all driver probes | Implement partial-probe unwind. | Fault injection after BAR map, IRQ alloc, DMA alloc, queue setup, and devfs/sysfs publish leaves no leaked binding, BAR VA, IRQ, DMA page, or node. |
| DVR-0005 | all drivers | Implement `shutdown()` behavior per device. | virtio devices reset/quiesce queues; storage flushes; net stops RX/TX; GPU restores/flushes; no QEMU timeout on reboot. |
| DVR-0006 | all singleton drivers | Replace global singleton runtime state with per-device state or explicitly reject second device during probe before publishing it. | Two-device QEMU test either exposes both devices correctly or exposes exactly one and leaves the other unbound with a clear sysfs/uevent state. |
| DVR-0007 | `crates/drivers/pci`, `hal-x86_64`, `firmware` | Implement x86 MCFG/ECAM PCIe config access; stop using CF8/CFC as the default PCI path. | q35 boot enumerates through ECAM; CF8/CFC only exists as fallback/debug and is not the normal Linux-compliance path. |
| DVR-0008 | `crates/drivers/pci` | Decode BAR size/range, not only programmed base. | `pci::decode_bars` or companion API returns base, size, type, prefetch; all drivers validate offset+length inside size. |
| DVR-0009 | `crates/kernel/sysfs/src/bus.rs` | Publish PCI `resource` and `resource0..resource5`. | `cat /sys/bus/pci/devices/0000:00:*.* /resource` matches Linux format enough for udev/libpci. |
| DVR-0010 | `sysfs/src/bus.rs` | Publish PCI `modalias`. | `cat /sys/bus/pci/devices/.../modalias` returns `pci:vVVVVdDDDDsv...bc...sc...i...`; `udevadm info` sees it. |
| DVR-0011 | `sysfs/src/bus.rs` | Publish PCI `revision`, `subsystem_vendor`, `subsystem_device`, `irq`, `enable`, `numa_node`, `driver_override`. | udev does not fail probing missing baseline PCI attributes. |
| DVR-0012 | `sysfs/src/bus.rs` | Add `subsystem` symlink for devices. | `/sys/bus/pci/devices/<bdf>/subsystem -> ../../../bus/pci` resolves. |
| DVR-0013 | `sysfs/src/bus.rs` | Add driver symlink backrefs and driver directory device symlinks. | `/sys/bus/pci/drivers/virtio-gpu/<bdf>` and device `/driver` both resolve like Linux. |
| DVR-0014 | `devfs`, `sysfs`, all char/block drivers | Add `/sys/dev/char/<maj>:<min>` and `/sys/dev/block/<maj>:<min>` symlinks. | `udevadm info --query=path --name=/dev/dri/card0` can resolve sysfs path. |
| DVR-0015 | all devfs inodes | Audit and fix `rdev()` for every device inode. | `stat -c '%t:%T'` on `/dev/dri/card0`, `/dev/input/event0`, `/dev/fb0`, `/dev/snd/*`, `/dev/vd*`, `/dev/tty*` matches assigned Linux major/minor plan. |
| DVR-0016 | `procfs/src/devices.rs` | Generate `/proc/devices` from actual registered char/block registries. | Newly registered DRM/input/sound/block devices appear without hard-coded edits. |
| DVR-0017 | `crates/drivers/drm/src/node.rs`, `drv-virtio-input` | Remove synthetic `EvdevInode` and `/proc/bus/input/devices` registration from DRM node code; input belongs to virtio-input/input core only. | There is exactly one owner for `/dev/input/event0`; no duplicate registration path. |
| DVR-0018 | `crates/drivers/drm` | Add per-open DRM file state. | Dumb handles, auth/master state, client caps, and event queues are per fd; two processes can open card0 without sharing handle tables. |
| DVR-0019 | `drm/src/node.rs` | Implement DRM `poll()` on card fds. | `poll(POLLIN)` wakes only when page-flip/hotplug event is queued. |
| DVR-0020 | `drm/src/node.rs` | Implement Linux card/render permission split. | Render node rejects modeset ioctls; card node requires master where Linux requires master. |
| DVR-0021 | `drm/src/node.rs` | Implement correct `GET_UNIQUE`, `GET_MAGIC`, `AUTH_MAGIC`, `GET_CLIENT`, `SET_MASTER`, `DROP_MASTER`. | libdrm legacy auth tests pass or fail in Linux-compatible ways. |
| DVR-0022 | `drm/src/modeset.rs`, `drm/src/crtc.rs` | Implement object property model. | `modetest -p` lists connector, CRTC, and plane properties. |
| DVR-0023 | `drm` | Implement `MODE_OBJ_GETPROPERTIES`. | `DRM_IOCTL_MODE_OBJ_GETPROPERTIES` returns real property IDs/values for connector, CRTC, plane, FB. |
| DVR-0024 | `drm` | Implement `MODE_GETPROPERTY`. | libdrm can decode property names, flags, enum/blob metadata. |
| DVR-0025 | `drm` | Implement blob lifecycle: `CREATEPROPBLOB`, `GETPROPBLOB`, `DESTROYPROPBLOB`. | Atomic userspace can create a mode blob and read EDID blob. |
| DVR-0026 | `drm` | Expose EDID as connector blob if virtio-gpu `GET_EDID` works; otherwise do not advertise EDID. | `modetest -c` shows EDID property with valid blob or no false EDID property. |
| DVR-0027 | `drm` | Implement real `MODE_ATOMIC`, not zero-object `TEST_ONLY` only. | `modetest -a` can do a modeset using atomic path. |
| DVR-0028 | `drm` | Implement `MODE_ATOMIC_TEST_ONLY` validation. | Invalid object/property/mode tuples fail without mutating state; valid tuples return 0. |
| DVR-0029 | `drm` | Implement `MODE_ATOMIC_ALLOW_MODESET` semantics. | Modeset-changing atomic commit without flag returns `EINVAL`; with flag applies. |
| DVR-0030 | `drm` | Implement page-flip event queue per fd. | `DRM_MODE_PAGE_FLIP_EVENT` returns a pollable `drm_event_vblank` with correct length, type, user_data, sequence, crtc_id. |
| DVR-0031 | `drm` | Implement hotplug event plumbing. | Synthetic virtio-gpu display-change posts `DRM_EVENT_HOTPLUG` to every card fd. |
| DVR-0032 | `drm` | Implement `MODE_DIRTYFB` or do not rely on it. | Front-buffer userspace can dirty/flush or gets Linux-compatible `ENOTTY/EINVAL` and caps do not imply support. |
| DVR-0033 | `drm` | Implement cursor plane or cursor ioctls. | Mutter/libdrm cursor setup either works or no cursor capability/properties are advertised. |
| DVR-0034 | `drm` | Fix capability reporting to match implementation. | `DRM_CAP_PRIME`, `SYNCOBJ`, `SYNCOBJ_TIMELINE`, `ADDFB2_MODIFIERS`, cursor caps are 0 unless fully supported. |
| DVR-0035 | `drm` | Implement PRIME only if real fd export/import exists. | `PRIME_HANDLE_TO_FD` returns a usable fd and `PRIME_FD_TO_HANDLE` imports it, or `DRM_CAP_PRIME=0`. |
| DVR-0036 | `drm` | Implement syncobj/timeline or report unsupported. | If caps are 1, all syncobj ioctls pass libdrm syncobj tests. |
| DVR-0037 | `drm/dumb.rs` | Make dumb handle lifetime per fd and refcount mmap/fb references correctly. | Closing fd frees handles only after mmap/fb refs are gone; no global handle collision between processes. |
| DVR-0038 | `drm/dumb.rs`, `syscalls/mmap` | Validate DRM mmap cookies, offset, length, and protections. | Bad offset/length returns Linux-compatible error; valid `MAP_SHARED` maps the buffer. |
| DVR-0039 | `drm` | Add `/sys/class/drm/card0`, `/sys/class/drm/renderD128`, connector class nodes. | `udevadm info /dev/dri/card0` and `loginctl` DRM device discovery work. |
| DVR-0040 | `drv-virtio-gpu` | Move virtio-gpu queue setup/probe out of `pci-boot`. | `drv-virtio-gpu::probe` owns common cfg, notify cfg, queues, device cfg, scanouts, DRM registration. |
| DVR-0041 | `drv-virtio-gpu` | Implement per-device command submission engine. | Command path serializes requests, tracks completions, checks response types, and returns errors instead of blind success. |
| DVR-0042 | `drv-virtio-gpu` | Implement interrupt or bounded worker completion handling. | GPU commands do not spin forever; queue completions wake waiters. |
| DVR-0043 | `drv-virtio-gpu` | Implement `GET_EDID` path. | Valid EDID bytes exposed to DRM connector blob when host advertises `VIRTIO_GPU_F_EDID`. |
| DVR-0044 | `drv-virtio-gpu` | Implement display-info refresh and scanout hotplug/update. | Display change updates DRM resources/connectors and emits event. |
| DVR-0045 | `drv-virtio-gpu` | Implement resource detach/unref on FB destroy and driver remove. | Resource leak counter returns to zero after modeset client exits. |
| DVR-0046 | `drv-virtio-gpu` | Support non-contiguous backing mem-entry lists safely. | Large buffers attach with bounded command allocation; no 4 KiB command buffer overflow. |
| DVR-0047 | `drv-virtio-gpu` | Gate VIRGL/blob/context feature bits honestly. | If features are negotiated, userspace can use them; otherwise not advertised. |
| DVR-0048 | `drv-virtio-input` | Make EVIOCGRAB per fd. | A grabbed event fd prevents other fds from receiving events like Linux evdev. |
| DVR-0049 | `drv-virtio-input` | Implement EVIOCSCLOCKID per fd. | Event timestamps use selected clock or return Linux-compatible error. |
| DVR-0050 | `drv-virtio-input` | Implement EVIOCREVOKE semantics. | Revoked fds stop receiving events and future I/O fails as Linux expects. |
| DVR-0051 | `drv-virtio-input` | Implement status queue for LEDs/repeat where device supports it. | `EVIOCSLED`/repeat writes change status or fail honestly; no fake success. |
| DVR-0052 | `drv-virtio-input`, `sysfs` | Publish `/sys/class/input/inputN` and `/sys/class/input/eventN`. | `libinput list-devices` discovers keyboard and pointer through sysfs. |
| DVR-0053 | `drv-virtio-input` | Add SYN_DROPPED on queue overflow. | Overflow inserts `SYN_DROPPED` in event stream before resync. |
| DVR-0054 | `drv-virtio-input` | Validate multitouch/tablet capability exposure. | Pointer device exposes correct ABS/REL/PROP bits; libinput does not reject it. |
| DVR-0055 | `devfs/misc`, `syscalls/getrandom` | Replace LCG random fallback with real CRNG. | `getrandom()` never returns deterministic LCG bytes; CRNG seeded from virtio-rng/RDRAND/boot entropy. |
| DVR-0056 | RNG | Implement Linux random readiness semantics. | Early `getrandom(0)` blocks or returns `EAGAIN` per flags until CRNG ready; `/dev/urandom` semantics are intentional and documented. |
| DVR-0057 | `drv-virtio-rng`, `sysfs` | Publish hwrng sysfs/class metadata. | `/sys/class/misc/hw_random` or equivalent expected hwrng path resolves if `/dev/hwrng` exists. |
| DVR-0058 | `block`, `devfs`, storage drivers | Publish block device nodes `/dev/vda`, `/dev/vdb`, `/dev/nvme0n1`, `/dev/sdX` with correct majors/minors. | `lsblk` sees block devices through `/sys/dev/block` and `/dev`. |
| DVR-0059 | `sysfs/src/block.rs` | Add `/sys/block/<disk>/device` symlink. | `udevadm info --name=/dev/vda` resolves parent device. |
| DVR-0060 | `sysfs/src/block.rs` | Add `/sys/block/<disk>/queue` baseline attributes beyond logical/physical size. | `lsblk`/udev can read at least `rotational`, `scheduler`, `read_ahead_kb`, `minimum_io_size`, `optimal_io_size`, `max_sectors_kb`. |
| DVR-0061 | `block` | Implement partition scanning and partition sysfs/dev nodes. | A disk with GPT exposes `/dev/vda1` and `/sys/block/vda/vda1`. |
| DVR-0062 | `drv-virtio-blk` | Implement read-only feature and config handling. | Read-only virtio disk sets `ro=1`, writes return `EROFS`. |
| DVR-0063 | `drv-virtio-blk` | Implement flush/discard/write-zeroes feature negotiation honestly. | If advertised, operations work; otherwise block layer returns `EOPNOTSUPP`. |
| DVR-0064 | `drv-virtio-net`, `net`, `sysfs` | Make virtio-net a real per-device netdev. | Multiple virtio-net devices become `eth0`, `eth1` with unique ifindex/MAC. |
| DVR-0065 | `drv-virtio-net` | Replace one RX buffer with RX buffer pool. | Sustained ping/DHCP/TCP under load does not drop all but one frame. |
| DVR-0066 | `drv-virtio-net` | Implement TX completion reclamation. | TX ring cannot wedge after repeated sends; completions advance and buffers recycle. |
| DVR-0067 | `drv-virtio-net` | Implement link status/carrier reporting. | `/sys/class/net/eth0/carrier`, flags, and netlink `RTM_NEWLINK` reflect state. |
| DVR-0068 | `drv-virtio-net` | Publish complete `/sys/class/net/<if>` baseline. | systemd-networkd/NetworkManager can enumerate iface without missing core attrs. |
| DVR-0069 | `drv-virtio-snd`, `kernel/sound` | Add ALSA sysfs/class/proc publication. | `aplay -l` discovers card/device through ALSA/libasound paths. |
| DVR-0070 | `kernel/sound/pcm.rs` | Implement PCM poll readiness. | `poll()` on PCM fd wakes for playback/capture period readiness. |
| DVR-0071 | `kernel/sound/pcm.rs` | Ensure advertised PCM info flags match implementation. | No mmap/async flags unless mmap/async are implemented. |
| DVR-0072 | `drv-virtio-snd` | Make playback/capture per-substream, not singleton-only. | Multiple opens either serialize with Linux-compatible busy errors or have separate runtime state. |
| DVR-0073 | `kernel/sound/control.rs` | Complete ALSA control ioctls expected by alsa-lib. | `aplay -l`, `amixer`, and `speaker-test` do not fail on missing mandatory control ioctls. |
| DVR-0074 | `tty`, `vt`, `vtconsole`, `sysfs` | Publish Linux tty class. | `/sys/class/tty/tty0`, `tty1`, `console`, `ptmx`, `ttyS0` resolve with dev attrs. |
| DVR-0075 | `vt` | Validate `KDSETMODE(KD_GRAPHICS)`/`KD_TEXT` with DRM master clients. | GDM/mutter can take graphics mode and console restores on exit. |
| DVR-0076 | `vt` | Validate `VT_ACTIVATE`, `VT_WAITACTIVE`, `VT_RELDISP`, foreground ownership. | `chvt`, logind seat switching, and X/Wayland VT handoff work. |

## PCI / BAR / Malformed Device Ledger

| ID | Area | What needs doing | Done |
|---|---|---|---|
| DVR-0100 | `pci::capabilities` | Fuzz cap-list cycles, out-of-range offsets, duplicate caps, bad alignments. | Unit/fuzz test suite verifies walker stops safely and never panics. |
| DVR-0101 | `virtio::pci::decode_one` | Reject virtio caps with bad `cap_len`, invalid BAR, zero length, offset overflow. | Bad-cap tests return `None` or typed error before BAR mapping. |
| DVR-0102 | `pci_boot::virtio_qsetup` | Validate queue size is power-of-two and ring fits allocation. | Malformed queue sizes fail probe, not boot. |
| DVR-0103 | virtio probe | If `FEATURES_OK` is not accepted, set FAILED/reset and leave device unbound. | Fault-injected device appears unbound in sysfs. |
| DVR-0104 | virtio probe | Bound all status waits with real timeout. | Dead device cannot hang boot indefinitely. |
| DVR-0105 | virtio probe | Validate notify cap and notify offset against BAR size. | Bad notify cap fails probe before mapping/writing. |
| DVR-0106 | MSI-X | Validate MSI-X table and PBA lie inside decoded BAR. | Bad table cap falls back or fails with logged reason. |
| DVR-0107 | DMA | Add device DMA mask/addressability checks. | Driver rejects allocations outside mask or uses bounce/IOMMU path. |
| DVR-0108 | MMIO mapping | Track and unmap driver BAR mappings on remove. | Bind/unbind loop does not consume VA space. |
| DVR-0109 | IRQ | Track and free MSI/MSI-X/INTx handlers on remove. | Bind/unbind loop does not leak vectors. |
| DVR-0110 | all drivers | Add timeout-to-error conversion for command submissions. | Timeout returns `EIO/ETIMEDOUT` equivalent and unwinds, not silent success. |

## DRM/KMS Detailed Ledger

| ID | Area | What needs doing | Done |
|---|---|---|---|
| DVR-0200 | `drm/src/lib.rs` | Compare every DRM ioctl number and struct size against current Linux headers. | Generated/checked constants test fails on mismatch. |
| DVR-0201 | `drm/src/node.rs` | Return `ENOTTY` for unknown ioctl, `EFAULT` for bad user pointer, `EINVAL` for malformed known request consistently. | ioctl errno conformance tests pass. |
| DVR-0202 | `drm` | Add card0/renderD128 Linux majors/minors: DRM major 226, minors 0 and 128. | `stat /dev/dri/card0` reports `226:0`; render reports `226:128`. |
| DVR-0203 | `drm` | Add `/dev/dri/by-path` symlink if userspace expects PCI path. | `/dev/dri/by-path/pci-0000:..-card` resolves where appropriate. |
| DVR-0204 | `drm` | Implement `GET_MAP`, `GET_STATS`, `GEM_CLOSE`, or intentionally return Linux-compatible errors. | libdrm probes do not break on missing legacy calls. |
| DVR-0205 | `drm` | Implement framebuffer enumeration in `GETRESOURCES` after `ADDFB`. | `count_fbs` and fb id list reflect live FBs. |
| DVR-0206 | `drm` | Implement `GETFB`. | `drmModeGetFB` returns width, height, depth, bpp, pitch, handle. |
| DVR-0207 | `drm` | Implement `RMFB` ownership and in-use checks. | Removing active fb behaves like Linux or fails with correct errno. |
| DVR-0208 | `drm` | Implement `SETPLANE` for primary plane at minimum. | Atomic/legacy plane setting updates CRTC scanout. |
| DVR-0209 | `drm` | Implement `GETPLANERESOURCES`/`GETPLANE` with universal plane client cap semantics. | Plane visibility matches `DRM_CLIENT_CAP_UNIVERSAL_PLANES`. |
| DVR-0210 | `drm` | Implement format modifier enumeration or report modifier cap 0. | `modetest` does not see modifier support unless `ADDFB2` modifiers work. |
| DVR-0211 | `drm` | Validate `ADDFB2` handles, pitches, offsets, fourcc, modifiers. | Bad fb creation fails with `EINVAL`; valid XRGB8888/ARGB8888 works. |
| DVR-0212 | `drm` | Implement gamma get/set or return correct unsupported behavior. | Compositor gamma probing does not get fake success. |
| DVR-0213 | `drm` | Implement close cleanup for DRM fds. | Handles, event subscriptions, master state, and client state are cleaned on close. |
| DVR-0214 | `drm` | Implement render-node allowed ioctl mask. | Modeset ioctls on render node fail; buffer ioctls allowed only if Linux allows. |
| DVR-0215 | `drm` | Add tests with `modetest`, `kmscube`, `weston-simple-dmabuf` where applicable. | Tests run in boot image and produce pass/fail logs. |

## Virtio Detailed Ledger

| ID | Area | What needs doing | Done |
|---|---|---|---|
| DVR-0300 | common virtio | Make a reusable modern virtio transport object. | All virtio drivers share status/feature/queue/MSI/notify setup code through a typed API. |
| DVR-0301 | common virtio | Implement queue reset where supported. | Remove/unbind resets queues cleanly or resets whole device. |
| DVR-0302 | common virtio | Implement interrupt-driven queue completion path. | At least net/input/gpu/snd use interrupts or a worker, not pure spin poll. |
| DVR-0303 | common virtio | Support more than 8 queues. | Device with >8 queues does not truncate silently; driver selects required queues. |
| DVR-0304 | common virtio | Implement config generation stable reads. | Device config reads retry if generation changes. |
| DVR-0305 | common virtio | Implement `DEVICE_NEEDS_RESET` handling. | Device reset condition tears down and marks interface down/unbound. |
| DVR-0306 | virtio-gpu | Implement cursor queue. | Hardware cursor movement/update works or cursor caps stay disabled. |
| DVR-0307 | virtio-input | Program eventq and statusq as independent queues with lifecycle. | Keyboard and pointer events continue after sustained use; LED/status writes go to statusq. |
| DVR-0308 | virtio-blk | Use device config generation when reading capacity/blk_size. | Capacity/blk size stable under config change. |
| DVR-0309 | virtio-net | Negotiate features intentionally and document unsupported offloads. | Feature bits in driver status reflect implemented data path. |
| DVR-0310 | virtio-net | Implement control virtqueue if MAC/link/MTU/offload features require it. | Changing MAC/MTU/link state works or features not exposed. |
| DVR-0311 | virtio-snd | Program eventq and handle jack/control events. | ALSA sees jack/control change events or no such controls are advertised. |
| DVR-0312 | virtio-vsock | Audit stream credit/window update implementation. | `socat`/vsock smoke can pass bidirectional stream data without deadlock. |

## Storage Ledger

| ID | Area | What needs doing | Done |
|---|---|---|---|
| DVR-0400 | `block` | Add central block major allocator/registry. | No static prefix guessing for majors/minors. |
| DVR-0401 | `block` | Add request queue limits. | `/sys/block/<disk>/queue/*` reflects driver max sectors, logical/physical size, discard. |
| DVR-0402 | `block` | Add partition parser for GPT/MBR. | `/proc/partitions` and `/sys/block/<disk>/<part>` reflect real partitions. |
| DVR-0403 | `block` | Add uevents for disk and partition add/remove/change. | `udevadm monitor` sees block add events. |
| DVR-0404 | `drv-nvme` | Enumerate namespaces instead of hardcoding nsid 1. | QEMU with two namespaces exposes both. |
| DVR-0405 | `drv-nvme` | Add `/dev/nvme0` controller char node. | Basic NVMe admin ioctl probes return correct data or errors. |
| DVR-0406 | `drv-nvme` | Implement MSI-X completion queues. | I/O does not poll-only under normal path. |
| DVR-0407 | `drv-nvme` | Add multi-page PRP/SGL support. | I/O larger than 4 KiB is one command or bounded scatter, not forced single-page bounce only. |
| DVR-0408 | `drv-nvme` | Implement dataset management/discard if supported. | `blkdiscard` works or reports unsupported. |
| DVR-0409 | `drv-ahci` | Enumerate all implemented SATA disk ports. | QEMU with two AHCI disks exposes two block devices. |
| DVR-0410 | `drv-ahci` | Rename/publish AHCI disks as Linux-like `sdX` unless there is a deliberate compatibility reason not to. | `lsblk` sees `sda`, `sdb` for AHCI. |
| DVR-0411 | `drv-ahci` | Implement AHCI interrupts and error recovery. | I/O completion and errors are interrupt-driven; bad disk does not wedge port forever. |
| DVR-0412 | `drv-ahci` | Implement TRIM/DATA SET MANAGEMENT if supported. | `blkdiscard` works or reports unsupported. |
| DVR-0413 | `drv-virtio-blk` | Support multiple virtio-blk disks. | `vda`, `vdb`, ... appear with correct serials and sysfs parents. |

## Network Ledger

| ID | Area | What needs doing | Done |
|---|---|---|---|
| DVR-0500 | `netdev`, `drv-virtio-net` | Create a proper netdev registration API for driver instances. | Driver registers `NetDevice` with ops, stats, carrier, MTU, MAC. |
| DVR-0501 | `drv-virtio-net` | Implement NAPI-like RX drain budget or softirq budget. | RX cannot starve scheduler under flood. |
| DVR-0502 | `drv-virtio-net` | Implement MTU set/get and validate against buffer size. | `ip link set dev eth0 mtu 1400` updates sysfs/netlink or fails correctly. |
| DVR-0503 | `drv-virtio-net` | Implement multicast/promiscuous mode hooks. | `ip maddr`, DHCP, IPv6 ND/multicast work reliably. |
| DVR-0504 | `net`, `sysfs` | Complete `/sys/class/net/<if>` baseline attributes. | `iproute2`, systemd-networkd, and NetworkManager probes pass. |
| DVR-0505 | `netlink` | Emit RTM_NEWLINK for interface add/change. | `ip monitor link` sees iface creation and carrier changes. |
| DVR-0506 | `drv-virtio-net` | Add stats counters matching Linux names. | `/sys/class/net/eth0/statistics/*` and `/proc/net/dev` match traffic. |

## Input / VT / TTY Ledger

| ID | Area | What needs doing | Done |
|---|---|---|---|
| DVR-0600 | `drv-virtio-input` | Add per-fd evdev state object. | Reads, grabs, clock id, revoke are per open file. |
| DVR-0601 | `drv-virtio-input` | Add input device sysfs metadata: name, phys, uniq, id, capabilities. | `/sys/class/input/input0/{name,phys,uniq,id/*,capabilities/*}` exists. |
| DVR-0602 | `drv-virtio-input` | Emit input uevents. | `udevadm monitor` sees input/event add events. |
| DVR-0603 | `drv-ps2-keyboard` | Decide PS/2 as real Linux input device or fallback-only. | If enabled, it publishes a distinct input device; otherwise it does not fake one. |
| DVR-0604 | `drv-ps2-keyboard` | Add IRQ1 path or document polling with tests. | Sustained keyboard input does not lose events under CPU load. |
| DVR-0605 | `tty` | Audit tty ioctl errno and struct layout. | `stty -a`, `login`, shell job control, and PTY smokes pass. |
| DVR-0606 | `vt` | Complete KD font/palette ioctls if advertised. | `setfont`, `kbd_mode`, `dumpkeys/loadkeys` expected paths pass or fail honestly. |
| DVR-0607 | `vt` | Complete VT process mode handoff. | X/GDM/logind can use VT_PROCESS and receive release/acquire signals. |
| DVR-0608 | `devpts` | Validate PTY major/minor and `/dev/ptmx` behavior. | `script`, `ssh`, terminal emulators allocate PTYs correctly. |

## Sound Ledger

| ID | Area | What needs doing | Done |
|---|---|---|---|
| DVR-0700 | `sound/control.rs` | Enumerate ALSA card/device/control info fully enough for alsa-lib. | `aplay -l`, `arecord -l`, `amixer contents` complete. |
| DVR-0701 | `sound/pcm.rs`, `sound/capture.rs` | Add PCM poll/select readiness. | `aplay` blocking and poll-driven modes work. |
| DVR-0702 | `sound` | Add `/proc/asound` minimum shape if alsa-lib expects it. | alsa-lib does not fail due missing `/proc/asound/cards`, `devices`, `pcm`. |
| DVR-0703 | `sound`, `sysfs` | Add `/sys/class/sound/*` nodes. | udev creates/recognizes ALSA device nodes from sysfs. |
| DVR-0704 | `drv-virtio-snd` | Handle virtio-snd eventq. | Jack/control events are delivered or not advertised. |
| DVR-0705 | `sound` | Add mmap PCM only if advertised. | If mmap flags are set, mmap playback/capture works; otherwise flags stay clear. |
| DVR-0706 | `sound` | Validate OSS compat does not mask ALSA bugs. | `/dev/dsp` works as compat, but ALSA primary path is the pass gate. |

## Framebuffer / Console Ledger

| ID | Area | What needs doing | Done |
|---|---|---|---|
| DVR-0800 | `fbdev`, `sysfs` | Publish `/sys/class/graphics/fb0`. | `udevadm info --name=/dev/fb0` resolves graphics class. |
| DVR-0801 | `fbdev` | Validate every implemented FBIO ioctl against Linux `fb.h`. | `fbset`, `fbdev_probe`, mmap write, colormap tests pass. |
| DVR-0802 | `fbdev` | Ensure unsupported FBIO ioctls return Linux-compatible errors. | Probe suite sees no fake success. |
| DVR-0803 | `fbcon` | Validate console restore after DRM client exits. | Kill modeset client; text console repaints correctly. |
| DVR-0804 | `fbcon`, `vt` | Validate KD_GRAPHICS suppresses text drawing. | When GDM owns VT in graphics mode, printk/fbcon does not corrupt scanout. |

## Serial Ledger

| ID | Area | What needs doing | Done |
|---|---|---|---|
| DVR-0900 | `drv-uart-16550`, `drv-uart-pl011` | Move UART detection into real platform/ACPI probe. | `platform/serial0` binds through driver model, not post-hoc no-op model driver. |
| DVR-0901 | `serialtty`, `sysfs` | Publish serial tty class nodes. | `/sys/class/tty/ttyS0` or `/sys/class/tty/ttyAMA0` exists with dev attr. |
| DVR-0902 | `drv-uart-pl011` | Add interrupt-driven RX. | PL011 receive works without tick polling. |
| DVR-0903 | UART drivers | Implement baud/termios programming or report fixed console limitations honestly. | `stty speed/parity/csize` behavior matches supported hardware mode. |
| DVR-0904 | UART drivers | Implement break/error/modem-control handling where relevant. | Serial conformance probes do not get fake success. |

## Devfs / Sysfs / Uevent Ledger

| ID | Area | What needs doing | Done |
|---|---|---|---|
| DVR-1000 | `devfs` | Add central char device registry. | Device nodes are registered with major/minor/name/class; `/proc/devices` and `/sys/dev/char` derive from it. |
| DVR-1001 | `block` | Add central block device registry with devtmpfs integration. | Block nodes appear automatically from block registration. |
| DVR-1002 | `netlink` uevent | Emit add/remove/change with correct env: `ACTION`, `DEVPATH`, `SUBSYSTEM`, `MAJOR`, `MINOR`, `DEVNAME`, `MODALIAS`. | `udevadm monitor --kernel --property` sees Linux-shaped events. |
| DVR-1003 | `sysfs` | Add `/sys/devices/virtual/*` for virtual devices. | DRM/input/sound/fb/tty virtual class paths resolve. |
| DVR-1004 | `sysfs` | Add `uevent` write behavior where Linux allows retrigger. | `echo add > /sys/.../uevent` emits event. |
| DVR-1005 | `sysfs` | Fix bus inference for `register_driver`; do not publish every driver under PCI only. | Platform, virtio, PCI, virtual drivers appear under correct bus/class. |
| DVR-1006 | `procfs` | Add `/proc/bus/input/devices` from real input registry. | It lists actual input devices and handlers. |
| DVR-1007 | `procfs` | Add `/proc/tty/drivers`, `/proc/tty/driver/serial` if expected by probes. | tty/serial tools do not fail due missing proc entries. |

## Test Ledger

| ID | Test | Pass condition |
|---|---|---|
| DVR-1100 | `udevadm info --export-db` | Completes without missing mandatory sysfs paths for PCI, DRM, input, block, sound, tty. |
| DVR-1101 | `udevadm trigger --action=add` | Retriggers events; no kernel panic; devices are rediscovered. |
| DVR-1102 | `modetest -c -p -a` | Lists connector/CRTC/planes/properties and performs atomic modeset. |
| DVR-1103 | `kmscube` or minimal GBM/EGL probe | Opens render/card nodes and presents frames, or fails only because 3D intentionally unsupported while 2D KMS works. |
| DVR-1104 | `weston --backend=drm-backend.so` or Mutter DRM probe | Gets past DRM/input probing. |
| DVR-1105 | `libinput list-devices` | Lists keyboard and pointer with capabilities. |
| DVR-1106 | `evtest /dev/input/event0` | Shows real key events, correct timestamps, SYN_REPORT, no duplicate devices. |
| DVR-1107 | `lsblk -o NAME,MAJ:MIN,SIZE,RO,TYPE` | Shows disks and partitions with correct sysfs/dev nodes. |
| DVR-1108 | `fio` read/write smoke | Sustained storage I/O succeeds across virtio-blk, NVMe, AHCI targets. |
| DVR-1109 | `ip link`, DHCP, ping, TCP smoke | virtio-net works under repeated traffic and reports stats. |
| DVR-1110 | `aplay -l`, `speaker-test`, `arecord` | ALSA discovery and playback/capture work or unsupported paths are not advertised. |
| DVR-1111 | `stty -a`, `getty`, PTY allocation | tty/serial/pty behavior matches Linux expectations. |
| DVR-1112 | malformed PCI/virtio emulator suite | Bad BAR/cap/queue/MSI/device status cases fail probe cleanly. |
| DVR-1113 | bind/unbind loop | 100 bind/unbind cycles for a non-root test device leak no IRQs, DMA pages, VA mappings, sysfs nodes, or devfs nodes. |
| DVR-1114 | reboot/poweroff | Every bound driver's `shutdown()` runs and QEMU exits/reboots cleanly. |
| DVR-1115 | GDM boot | systemd reaches graphical target; GDM starts; Mutter opens DRM/input; no fake-success driver probe causes crash. |

## Immediate Order of Attack

1. `DVR-0001` through `DVR-0006`: real driver instances and lifecycle.
2. `DVR-0007` through `DVR-0016`: PCI/devfs/sysfs baseline so udev has a Linux-shaped machine.
3. `DVR-0017` through `DVR-0039`: DRM/input cleanup and real KMS path for GDM.
4. `DVR-0040` through `DVR-0047`: virtio-gpu backend correctness.
5. `DVR-0058` through `DVR-0068`: block/net device publication and runtime robustness for systemd.
6. `DVR-0069` through `DVR-0076`: sound/tty/VT completion for desktop session quality.
7. `DVR-0100` through `DVR-0110`: malformed-device hardening. This is the "no missing BAR or malformed systems" gate.
