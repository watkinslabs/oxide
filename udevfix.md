# udev correctness fix plan

Date: 2026-07-03

## Position

udev itself is not supposed to be a kernel subsystem.

On Linux, the kernel provides:

- `devtmpfs` device nodes under `/dev`
- `sysfs` kobjects and attributes under `/sys`
- `NETLINK_KOBJECT_UEVENT` raw kernel events
- correct major/minor metadata, parent/child topology, class/bus links, and remove/change/add lifecycle

Userspace provides:

- `systemd-udevd`
- rule evaluation
- tags such as `master-of-seat`
- permissions, ownership, symlinks, hwdb properties, and cooked libudev monitor events

Oxide should not implement udev rules in the kernel. The kernel must instead expose a Linux-shaped device model that real udev can consume. Any behavior that belongs to udev rules, hwdb, persistent naming policy, permissions policy, or seat tagging must stay in userspace. Any kernel shortcut that bakes those policy decisions into the kernel is wrong and must be removed or avoided.

The current implementation is halfway between a kernel-populated static device world and Linux's kobject/devtmpfs/uevent contract. That must be corrected.

## Current assessment

The strongest current blocker is `NETLINK_KOBJECT_UEVENT` cooked-event delivery.

Kernel-originated raw uevents now correctly go only to group 1 in `crates/kernel/netlink/src/lib.rs`. That matches Linux's raw kernel event path and fixed the prior systemd storm where PID1 received a raw blob on its cooked monitor path.

The missing half is userspace-to-userspace cooked multicast. `systemd-udevd` receives raw kernel events, applies rules, then rebroadcasts cooked libudev events to monitor clients such as PID1/logind. In the current code, userspace `sendto()` on a uevent netlink socket is routed through generic request/reply handling. There is no proper `NETLINK_KOBJECT_UEVENT` send-side multicast path for cooked messages, so logind/systemd can miss processed udev events.

For the graphical path, that means:

1. Kernel emits raw DRM `add`.
2. udevd receives it on group 1.
3. udevd should apply `71-seat.rules`, adding `master-of-seat`.
4. udevd should broadcast a cooked event.
5. systemd/logind should receive that cooked event.
6. logind should mark `seat0` graphical.
7. gdm should open `/dev/dri/card0`.

The suspected break is step 4 to step 5.

## Things we are doing wrong

### 1. Treating udev as if kernel-side shortcuts can replace the Linux contract

The kernel should not emulate udev policy. It should expose enough Linux-compatible state for real udev to work.

Wrong direction:

- hard-coding policy outcomes in kernel
- creating userspace-facing shortcuts instead of fixing sysfs/devtmpfs/netlink
- relying on static `/dev` population as a substitute for device lifecycle

Correct direction:

- kernel emits correct add/change/remove events
- kernel exposes correct sysfs topology and attributes
- kernel creates coherent devtmpfs nodes
- userspace udev applies rules and policy

### 2. Missing cooked uevent multicast

Raw kernel uevents are filtered to group 1, which is correct.

But userspace-sent cooked udev messages are not multicast to monitor subscribers correctly. `sendto()` routes into `NetlinkSocket::write()`, which parses netlink headers as normal requests. That is not enough for `systemd-udevd` cooked rebroadcast.

This must be fixed first.

### 3. Incomplete writable `/sys/.../uevent`

Linux allows retriggering many devices by writing an action such as `add` to their `uevent` attribute. Oxide has this for some nodes, such as DRM, but not consistently across bus, block, input, sound, tty, fb, and other device classes.

`udevadm trigger --action=add` cannot be correct until every relevant kobject supports this.

### 4. Device registration ordering is not Linux-correct enough

`drv::device_add()` currently pushes the device into the registry and fires the sysfs hook, which emits the add uevent, before the devtmpfs hook creates the `/dev` node.

That means userspace can process an add event before the corresponding `/dev` node exists.

Linux's observable contract is that by the time userspace acts on a device add event, the sysfs object and devtmpfs node are coherent.

### 5. Remove/change lifecycle is incomplete

`device_del()` removes registry/devfs state but does not emit a matching remove uevent. Hot-unplug and rebinding will not be Linux-correct until add/change/remove are symmetrical.

### 6. `/sys/dev/char` and `/sys/dev/block` are missing

Linux exposes:

- `/sys/dev/char/<major>:<minor>`
- `/sys/dev/block/<major>:<minor>`

udev and libudev use these paths to resolve a `/dev` node back to its sysfs object. Without them, `udevadm info --name=/dev/...` is unreliable or broken.

### 7. PCI sysfs is too thin

Current PCI attributes are not enough for real userspace probing.

Missing or incomplete baseline pieces include:

- `modalias`
- `resource`
- `resource0..resource5`
- `revision`
- `subsystem_vendor`
- `subsystem_device`
- `irq`
- `enable`
- `numa_node`
- `driver_override`
- `subsystem` symlink
- device `driver` symlink
- driver directory backrefs

Without these, udev/libpci/systemd can fail or misclassify devices.

### 8. Block sysfs is too thin

Current `/sys/block/<dev>` support is minimal.

Missing or incomplete pieces include:

- writable `uevent`
- `/sys/dev/block/<major>:<minor>`
- `/sys/block/<disk>/device`
- partitions under `/sys/block/<disk>/<disk><part>`
- partition uevents
- queue attrs such as `rotational`, `scheduler`, `read_ahead_kb`, `minimum_io_size`, `optimal_io_size`, `max_sectors_kb`

### 9. Class coverage is incomplete

Linux userspace expects class devices for at least:

- DRM
- input
- sound
- graphics/fb
- tty
- block
- net
- misc where applicable

Every class device needs coherent `dev`, `uevent`, `subsystem`, parent linkage where applicable, and `/sys/dev/{char,block}` reverse lookup.

### 10. Event environment is not complete enough

Raw events must be Linux-shaped:

- header: `<action>@<devpath>`
- `ACTION=...`
- `DEVPATH=...`
- `SUBSYSTEM=...`
- `SEQNUM=...`
- `MAJOR=...` and `MINOR=...` for device nodes
- `DEVNAME=...` where applicable
- `DEVTYPE=...` where applicable
- `MODALIAS=...` where applicable

Subsystems should add expected domain-specific fields, not just the minimum fields that happen to satisfy one boot path.

## Fix plan

### Phase 1: fix uevent netlink semantics

Implement `NETLINK_KOBJECT_UEVENT` userspace send-side multicast.

Requirements:

- Raw kernel events still go only to group 1.
- Userspace-sent cooked libudev messages from udevd are delivered to monitor clients.
- Respect netlink group masks from `bind()` and `NETLINK_ADD_MEMBERSHIP`.
- Handle the observed systemd behavior where some monitors bind `nl_groups=0`; verify what Linux/systemd expects and match it closely enough for systemd/logind.
- Do not deliver raw kernel blobs to cooked-only monitors.
- Add tests for:
  - raw event reaches group-1 udevd socket only
  - raw event does not reach group-0 cooked monitor
  - cooked userspace event reaches subscribed monitor sockets
  - empty receive returns `EAGAIN`
  - poll readiness clears after consuming the datagram

Boot verification:

- trace udevd `sendmsg()` on `NETLINK_KOBJECT_UEVENT`
- trace systemd/logind `recvmsg()`
- prove DRM cooked event reaches logind
- prove `/dev/dri/card0` is opened after seat becomes graphical

### Phase 2: centralize uevent generation

Create a shared kernel helper for kobject uevent bodies and retrigger writes.

Requirements:

- every kobject gets consistent action parsing
- every kobject emits consistent raw event format
- `uevent` read body matches the event environment where Linux expects it
- `echo add > /sys/.../uevent` works for all relevant classes and buses

Apply this to:

- DRM
- tty
- net
- PCI
- virtio
- block
- input
- sound
- fb/graphics
- misc devices where applicable

### Phase 3: make `device_add` coherent

Fix registration ordering.

Correct observable order:

1. Register the device internally.
2. Prepare sysfs state.
3. Create devtmpfs node if the device has one.
4. Emit `add` uevent only after sysfs and devtmpfs are coherent.

Also fix `device_del()`:

1. Emit `remove` uevent at the right point.
2. Remove `/dev` node.
3. Remove registry/sysfs visibility.
4. Ensure stale `/sys/dev/{char,block}` links disappear.

Add `change` event helpers for binding, carrier changes, media changes, block rescan, DRM hotplug, etc.

### Phase 4: add central char/block registries and `/sys/dev`

Build `/sys/dev/char/<major>:<minor>` and `/sys/dev/block/<major>:<minor>` from real device registries.

Requirements:

- `udevadm info --query=path --name=/dev/dri/card0` resolves
- `udevadm info --query=path --name=/dev/vda` resolves
- tty/input/sound/fb nodes resolve
- `/proc/devices` is generated from the same registry, not hard-coded

### Phase 5: complete PCI baseline

Implement enough PCI sysfs for udev, libpci, systemd, and driver matching.

Required files and links:

- `vendor`
- `device`
- `class`
- `revision`
- `subsystem_vendor`
- `subsystem_device`
- `irq`
- `enable`
- `numa_node`
- `driver_override`
- `modalias`
- `resource`
- `resource0..resource5`
- `subsystem -> ../../../bus/pci`
- device `driver` symlink when bound
- driver directory backrefs

Required behavior:

- duplicate bind returns Linux-compatible error
- unbind removes binding and emits event
- bind/unbind loops do not leak IRQs, DMA, BAR mappings, sysfs nodes, or devfs nodes

### Phase 6: complete class and subsystem sysfs

Prioritize in this order:

1. DRM, because it blocks graphical seat detection.
2. input, because graphical login needs keyboard/pointer discovery.
3. block, because storage tools and mount generators depend on it.
4. tty, because systemd/getty/logind inspect it.
5. sound and fb/graphics.
6. net class refinements.

DRM minimum:

- `/dev/dri/card0` has `226:0`
- `/dev/dri/renderD128` has `226:128`
- `/sys/class/drm/card0`
- `/sys/class/drm/renderD128`
- `dev`
- writable `uevent`
- `subsystem`
- `/sys/dev/char/226:0`
- `/sys/dev/char/226:128`
- correct `DEVNAME=dri/card0`
- correct `DEVTYPE`
- hotplug `change` events

Input minimum:

- `/sys/class/input/inputN`
- `/sys/class/input/eventN`
- `name`
- `phys`
- `uniq`
- `id/*`
- `capabilities/*`
- `/sys/dev/char/13:*`
- input add/change/remove uevents

Block minimum:

- `/dev/vda`, `/dev/vdb`, etc.
- `/sys/block/vda`
- `/sys/dev/block/<major>:<minor>`
- `/sys/block/vda/device`
- queue baseline attrs
- partitions
- disk and partition add/remove/change uevents

### Phase 7: conformance tests

Add boot/runtime gates:

- `udevadm monitor --kernel --property`
- `udevadm monitor --udev --property`
- `udevadm trigger --action=add`
- `udevadm info --export-db`
- `udevadm info --name=/dev/dri/card0`
- `udevadm info --query=path --name=/dev/dri/card0`
- `loginctl seat-status seat0`
- `lsblk -o NAME,MAJ:MIN,SIZE,RO,TYPE`
- `libinput list-devices`
- `evtest /dev/input/event0`
- `aplay -l`
- `ip link`

Graphical pass condition:

- udevd processes DRM `card0`
- `master-of-seat` tag is applied by userspace udev rules
- cooked udev event reaches systemd/logind
- logind marks `seat0` graphical
- gdm opens `/dev/dri/card0`
- greeter starts

## Immediate next task

Implement and test `NETLINK_KOBJECT_UEVENT` userspace cooked multicast.

Do not start by adding kernel policy hacks for seats or DRM. That would hide the real bug and make the OS less Linux-compatible.

After cooked multicast works, run the graphical boot path with traces for:

- udevd raw event receive
- udevd cooked event send
- systemd/logind cooked event receive
- logind seat graphical transition
- `/dev/dri/card0` open

Only after that should DRM ioctl/KMS gaps be debugged, because currently the seat path appears to fail before logind opens the DRM node.
