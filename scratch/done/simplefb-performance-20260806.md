# Simple-framebuffer acceptance measurements — 2026-08-06

B1875 comparison record. The guest was a release-profile x86_64 kernel under
KVM with the bounded `debug-boot` operational pulse enabled, booted through
GRUB with QEMU std-VGA and no virtio-gpu. GRUB selected a 1280x800 packed-XRGB
framebuffer at physical `0xfd000000`, pitch 5120, depth 32: one full frame is
4,096,000 bytes. The debug feature emitted boot milestones but no output during
the timed write loop.

## Full-frame write comparison

The probe opened and wrote `/dev/fb0` 32 times with one 4,096,000-byte write
per iteration, for 131,072,000 bytes total (125 MiB). It measured the normal
driver WC mapping and then a one-line UC control using the same driver and
guest image. The UC control was restored immediately and was never committed.

| Mapping | vCPUs | Elapsed | System CPU | Throughput |
|---|---:|---:|---:|---:|
| Production WC | 2 | 0.27 s | 0.08 s | 463 MiB/s |
| Temporary UC control | 1 | 3.10 s | 1.57 s | 40.3 MiB/s |

The elapsed result is an 11.5x improvement and the coarse system-CPU sample is
19.6x lower. The probe is a single writer, so the CPU-count mismatch does not
create parallel write throughput; an exact one-vCPU WC rerun is retained
separately when available. These are QEMU VBE aperture measurements, not a
claim about one specific physical GPU or firmware.

Command run by the smoke harness:

```sh
/usr/bin/time -f 'B1875_FILL elapsed=%e user=%U sys=%S' \
  sh -c 'for i in $(seq 1 32); do dd if=/dev/zero of=/dev/fb0 bs=4096000 count=1 status=none; done'
```

The forced path also proved the complete fallback chain: the Multiboot2
framebuffer tag was decoded, `simplefb: registered WC framebuffer` appeared,
userspace reached the debug shell, and bidirectional serial RX passed. Source
logs at measurement time were `/tmp/b1875-simplefb-wc-bench.log`,
`/tmp/b1875-simplefb-uc-bench.log`, and `/tmp/b1875-simplefb.log`; the durable
inputs and results are recorded here because `/tmp` is not durable.

## Closed serial observation

Exact one-vCPU WC reruns exposed an intermittent pre-simplefb serial failure:
one stopped in the i8042 probe and another in AHCI enumeration; serial SysRq
produced no response in the bounded first run. One earlier UC attempt showed
the same pre-driver shape. B1876 closed it by draining the edge-triggered UART
IRQ line to deassertion with a bounded pass limit and raising the UART's `OUT2`
interrupt gate. Five exact one-vCPU forced-framebuffer boots then passed in
80/58/57/56/58 s with serial RX. The retained row is in `fixed-issues.md`; it
does not change the completed framebuffer result or hide the original B1875
observation.
