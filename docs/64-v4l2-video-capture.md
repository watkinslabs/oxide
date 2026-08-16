# 64 V4L2 video capture

DRAFT 2026-08-16. Dep:`01`,`02`,`06`,`07`,`08`,`09`,`13`,`15`,`16`,`19`,`22`,`23`,`34`,`35`,`52`,`53`,`60`. Provides:`v4l2`, `/dev/videoN`, the `video4linux` class, `drv-vivid`.

Full Linux compat surface: the video device core, the `VIDIOC_*` command set, the buffer queue with its three memory models, the control framework, and the event queue. No deferrals.

## 1 Purpose

A camera is the last device class a desktop needs and the only one this repository had no owner for at all. Nothing on any bus published a video node, so a video call, a camera panel and a barcode scanner each found no device at all, not a device that failed. `crates/kernel/v4l2` is the owner: it publishes `/dev/videoN`, answers the command surface an application speaks, and runs the buffer queue every capture driver streams through. `crates/drivers/drv-vivid` is its first driver — a virtual camera, so the path has a caller on a machine with no camera hardware.

## 2 Invariants (frozen)

1. `crates/kernel/v4l2` owns the user-visible V4L2 surface for every capture device: node publication and minor allocation, the file-handle model, the command dispatch and its error ordering, the buffer queue and its state machine, the control registry, the event queues, and the format arithmetic every driver shares. It owns no transport.
2. A driver supplies its identity, its capability mask in V4L2 terms, its format and frame-size tables, its inputs, its controls and its streaming callbacks through `v4l2::ops::VideoOps`. A transport-private encoding stays in the driver crate that owns that transport and is translated at the boundary.
3. Every decision that can be made without hardware is in an ungated module and is hosted-tested: command encoding and argument layout, format negotiation and clamping, size arithmetic per pixel format, the buffer state machine, allocation arithmetic, error ordering, priority arbitration, control range and step validation, the control query walk, menu validation, event delivery and overflow. The gated modules are the node, the copy in and out, the plane pages, the sleep and the registration (`53` shape).
4. One argument, copied in whole, worked on as bytes and copied back. A command handler never touches user memory except through the context's accessor, which is what keeps the whole surface testable.
5. Buffer pages are refcounted kernel RAM published through the shared-frame mapping path. Never a physical range: that path counts no reference, and the queue releasing its own would free a page userspace still maps.
6. The buffer queue holds no lock. The device serialises access; every rule in the queue subtree is a plain function.
7. A driver never invents a timestamp or a sequence number the hardware did not produce. Both ride in on the completion, because a program pacing on an invented stamp cannot tell it is invented.
8. Node publication goes through the driver model (`drv::try_device_add`), which is also what projects `/sys/class/video4linux/videoN` and sends the uevent a device manager acts on (`60`). There is no second path that creates a video node.
9. The command dispatch checks in one order and that order is the contract: device gone, then unknown command, then priority, then per-command validation. Each answer tells a different program a different true thing.
10. `docs/52§5` rule 13 records this ownership; rule 14 records `drv-vivid`'s.

## 3 Command surface

| Command | Answer |
|---|---|
| `QUERYCAP` | driver, card, bus, version, `capabilities` with the device-caps marker, `device_caps` without it |
| `ENUM_FMT` | the driver's table by index; past the end is `EINVAL` |
| `G_FMT` / `TRY_FMT` / `S_FMT` | negotiation per §4; `S_FMT` is `EBUSY` while buffers exist |
| `ENUM_FRAMESIZES` / `ENUM_FRAMEINTERVALS` | discrete entries by index; a size the format does not offer is `EINVAL` |
| `REQBUFS` | allocate, reallocate, or free on a count of zero |
| `CREATE_BUFS` | append without disturbing the pool; a second memory model is `EINVAL` |
| `QUERYBUF` / `QBUF` / `DQBUF` / `PREPARE_BUF` | §5 |
| `REMOVE_BUFS` | drop an idle run and renumber |
| `EXPBUF` | `EINVAL` until a descriptor exporter exists (`known_issues`) |
| `STREAMON` / `STREAMOFF` | §5 |
| `G_PARM` / `S_PARM` | the frame interval, clamped to the declared set and reported back |
| `ENUMINPUT` / `G_INPUT` / `S_INPUT` | the driver's inputs; switching is `EBUSY` while buffers exist |
| `ENUMSTD` / `G_STD` / `S_STD` / `QUERYSTD` | `ENOTTY` on a device with no analogue standard |
| `CROPCAP` / `G_CROP` / `S_CROP` / `G_SELECTION` / `S_SELECTION` | the whole frame; a smaller rectangle on a fixed-frame device is `EINVAL` |
| `G_CTRL` / `S_CTRL` / `QUERYCTRL` / `QUERYMENU` / `QUERY_EXT_CTRL` | §6 |
| `G_EXT_CTRLS` / `S_EXT_CTRLS` / `TRY_EXT_CTRLS` | §6; all-or-nothing, with the failing index reported |
| `SUBSCRIBE_EVENT` / `UNSUBSCRIBE_EVENT` / `DQEVENT` | §7 |
| `G_PRIORITY` / `S_PRIORITY` | §8 |
| `LOG_STATUS` | success, no output |

Any other V4L2-typed command is `ENOTTY`, the same answer a foreign command gets: an application probing for a feature must not be able to tell "this kernel does not implement it" from "this device does not have it".

## 4 Format negotiation (frozen)

1. A pixel format the device does not produce is replaced by the driver's preferred one — negotiation, not refusal.
2. The requested size is clamped to the nearest declared frame size by total pixel-count difference, ties to the earlier entry.
3. A progressive device reports `V4L2_FIELD_NONE` whatever was asked for. An interlaced one keeps a valid request and resolves the any-field selector to interlaced.
4. Colorimetry words outside their enumerations reset to their defaults; the call is not refused. An unspecified colorspace resolves to sRGB.
5. `bytesperline` and `sizeimage` are derived from the settled format: a product for a packed format, luma plus chroma for a planar one, and the driver's declared maximum for a compressed bytestream, whose stride is zero.
6. `TRY_FMT` predicts `S_FMT` exactly. The two differ only in whether the result is kept.

## 5 Buffer queue (frozen)

States are `Dequeued`, `InRequest`, `Preparing`, `Queued`, `Active`, `Done`, `Error`.

1. Only a buffer userspace owns may be queued. Everything else is `EINVAL` — that refusal is what stops a frame being delivered twice.
2. `PREPARE_BUF` admits only a dequeued, unprepared buffer.
3. A completion is believed only from `Active`. Any other origin is forced to `Error`, never trusted: acting on it would corrupt the done list.
4. `STREAMON` on a running queue succeeds and does nothing. With no buffers, or fewer queued than the driver's minimum, it is `EINVAL`. A refused `start_streaming` returns every handed buffer to `Queued` in its original order, so the pool is reusable unchanged.
5. `STREAMOFF` is unconditional and returns every buffer to `Dequeued` whatever it was doing. It succeeds on a queue that was never streaming.
6. `DQBUF` admission order: a second waiter is `EBUSY`, then not-streaming is `EINVAL`, then a failed queue is `EIO`, then the consumed end-of-stream marker is `EPIPE`, then an empty done list is `EAGAIN` for a non-blocking caller and a sleep otherwise.
7. A buffer that completed with an error is still handed back, carrying `V4L2_BUF_FLAG_ERROR`. Losing it would leak it out of the pool.
8. A buffer is described before it leaves the done list, so `V4L2_BUF_FLAG_DONE` reaches the caller.
9. A payload larger than its plane is clipped to the plane.
10. `REQBUFS` with a count of zero frees everything. While streaming it is `EBUSY`; with a reader parked in a blocking dequeue, a reallocating request is `EBUSY` and a freeing one is not.
11. A plane userspace still maps is orphaned on free, not retained: the queue drops its reference and the page dies with the last mapping.
12. The queue is owned by the file description that allocated it. A second handle's allocation is `EBUSY`, and the owner's close stops the transport and frees the pool.
13. Readiness: a stopped or failed queue is `POLLERR`, a completed buffer is `POLLIN`, the end-of-stream marker is `POLLIN` so the dequeue it provokes can report `EPIPE`, and a waiting event adds `POLLPRI` — never `POLLIN`.

## 6 Controls (frozen)

1. A value is snapped by rounding to the nearest step, half upward, then clamping, then truncating onto `minimum + k*step`. A maximum that is not itself on the grid is therefore unreachable; a driver that wants its maximum reachable puts it on the grid.
2. A menu index is a choice, not a slider: out of range is `ERANGE`, an entry the driver skipped is `EINVAL`, and neither is clamped. A boolean normalises, a button discards its value, a bitmask drops undeclared bits.
3. A driver range that cannot be satisfied is refused at registration, per type: a numeric control needs a non-zero step and an in-range default, a boolean has no step to choose, a bitmask has no minimum and a non-zero legal set, and a menu's skip mask reaches only the first 64 entries.
4. `QUERYCTRL` and `QUERY_EXT_CTRL` describe a disabled control and report `V4L2_CTRL_FLAG_DISABLED`; it is value access that refuses it with `EINVAL`. A control the device lacks is `EINVAL`, never `ENOENT`.
5. The walk flags select the next control above the given id — any kind, compound only, or simple only. Failure ends the enumeration with `EINVAL`.
6. The legacy 32-bit query refuses a compound control or a range that does not fit; truncating one leaves an application negotiating against a range the device does not have.
7. A cluster's dependants go inactive while the automatic control that governs them is engaged, and each change is announced, so a settings panel greys out the exposure time the moment automatic exposure is switched on.
8. An extended batch is validated in full before the first store; the failing entry's index is reported and nothing is applied. A successful batch leaves the index at the count.
9. The `which` selector chooses the live value, the default, or an end of the range. The request selector is `EINVAL` until request descriptors exist (`known_issues`).
10. Standard control names are the reference's. A renamed control is a missing control.

## 7 Events (frozen)

1. Per open file description, not per device: two programs watching one camera each have their own rings.
2. The catch-all type may be unsubscribed but never subscribed. Subscribing to a control the device lacks is `EINVAL`, because a waiter on an event that never fires hangs.
3. A full ring evicts its oldest event. A control ring is one deep, since the newest value is the only one worth having.
4. The per-handle sequence advances on every delivery to a subscribed handle, including one whose ring was full. A gap in it is the only signal an event was lost; nothing counts drops.
5. `DQEVENT` on an empty queue is `ENOENT` — deliberately not the buffer path's `EAGAIN`, and programs test for exactly that. `pending` is what remains after the dequeue.
6. A handle does not receive an event for its own write unless it subscribed with the feedback flag.

## 8 Priority (frozen)

The state-changing commands are arbitrated. A handle at a strictly lower priority than the highest one held gets `EBUSY`; equal priority shares the device. The unset level never blocks and is not settable. A handle releases its level at close, and the device's level falls only when the last holder of that level goes.

## 9 Node and class

`/dev/videoN` under major 81, minors `0..64` for `videoN` (the `radioN`, `vbiN` and `v4l-subdevN` ranges are reserved in `ids` and unpopulated). The `video4linux` class is projected by `sysfs`'s char-class mechanism, the same one `sound`, `graphics` and `input` use; there is no second class registry.

## 10 `drv-vivid`

A virtual capture device, published unconditionally at boot. Eight vertical colour bars scrolling one bar per frame, in `YUYV`, `UYVY`, `RGB24`, `BGR24`, `RGB565` and `GREY`, at four sizes and four frame intervals, with the standard camera control set. Frames are produced by a periodic timer that advances by whole periods so the nominal rate does not drift, and resynchronises after a stall longer than a second instead of bursting.

## 11 Test contract

Hosted, in ungated modules:

| Area | What must fail if it breaks |
|---|---|
| ABI | every command encoding rebuilt from direction, ordinal and argument size; every argument size the sum of its fields; every fourcc re-derived from its characters; every control id from its class and ordinal |
| Format | clamping, substitution, field resolution, colorimetry sanitising, size arithmetic per format, `TRY_FMT` predicting `S_FMT` |
| Buffers | the transition table exhaustively, completion origin, cancellation, reported flags |
| Queue | allocation arithmetic, cookie distinctness, memory-model refusal, growth, removal, ownership |
| Streaming | idempotent start, refused start unwinding, unconditional stop, completion order, payload clipping, the dequeue ladder, poll masks |
| Controls | the snap rule over a whole range, range coherence per type, menu refusal, the walk, batch atomicity, cluster inactivity |
| Events | the catch-all rules, overflow eviction, the sequence gap, arrival order, feedback |
| Order | unknown command, gone device, priority ladder, short arguments |

Every claim carries a positive control: the defect is reinstated, the tests go red, the defect is removed, they go green, and both counts are reported.

## 12 Open questions

- A descriptor exporter for buffer planes, which `EXPBUF` needs.
- Request descriptors, which the request `which` selector and the in-request buffer state need.
- The USB Video Class driver, which needs isochronous transfers the host-controller driver does not have yet.
