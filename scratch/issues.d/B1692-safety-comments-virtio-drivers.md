# B1692 — SAFETY comment audit, virtio + display + storage drivers

Audit of every `code/safety-missing` / `code/safety-short` finding in
`crates/drivers/{virtio,drv-virtio-*,drm,fbdev,fbcon,drv-nvme,drv-ahci}`.
Each block was read and its invariant established before a comment was written;
blocks that turned out unsound are rows below, not comments.

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| FIXED B1692 | HIGH | `program_queue` used the DEVICE-supplied `queue_size` unchecked while allocating exactly ONE frame per ring area. A device advertising more descriptors than a frame holds (QEMU accepts `queue-size=1024` on virtio-blk) makes every driver's own descriptor/avail/used store run off the end of that frame — a kernel heap wild write whose value comes from the ring index. Now renegotiated down per Virtio 1.2 §4.1.4.3 and the queue refused if the device does not accept. | `virtio::queue_cfg::tests::oversized_device_queue_size_is_negotiated_down_to_one_frame`; positive control: with the clamp disabled the test FAILS (`ring.size` 1024 vs 256), with it enabled it passes | B1692 |
