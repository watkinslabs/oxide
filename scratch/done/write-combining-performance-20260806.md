# Write-combining acceptance measurements — 2026-08-06

B1874 comparison record. Tests used clean release kernels with no `debug-*`
features. The Firefox workload ran under KVM on x86_64 with one vCPU; the
paired boot gate covered x86_64 and aarch64.

## Browser and syscall no-regression control

| Probe | B1873 exact final | B1874 |
|---|---:|---:|
| Valid page visually ready | 4.960 s | 4.950 s |
| Invalid-DNS page visually ready | 2.700 s | 1.461 s |
| Kernel cost/syscall, run 1 | 0.150 us | 0.153 us |
| Kernel cost/syscall, run 2 | 0.150 us | 0.155 us |
| Kernel cost/syscall, run 3 | 0.150 us | 0.153 us |
| HTTPS DNS + TCP + TLS + HTTP | 54.182 ms | 39.477 ms |

B1874 run `2088783` passed graphical OCR for both pages, Firefox liveness,
valid and invalid resolver checks, and the final resolver D-Bus health check.
GNOME's settled one-vCPU load was `0.86 0.24 0.08`. UART log:
`/tmp/oxide-firefox-uart-2088783.log`.

## Architecture and boot controls

| Probe | Result |
|---|---:|
| x86_64 Linux-compatible PAT value | `0x0407050600070106` |
| aarch64 MAIR value | `0x44ff04` |
| x86_64 userspace + serial RX | PASS, 76 s, attempt 1 |
| aarch64 userspace + serial RX | PASS, 154 s, attempt 1 |
| x86_64 HAL | 155 tests passed |
| aarch64 HAL | 149 tests passed |
| VMM | 337 tests passed |
| fbdev | 29 tests passed |

The demand-fault regression drives the production raw-PFN mapping path and
proves write-back RAM, write-combining framebuffer/MMIO, and strongly uncached
device mappings install distinct leaf policies. x86 tests pin the WC, UC-, UC,
WT, and legacy-errata PAT encodings, including 4 KiB versus large-leaf PAT bit
placement. arm64 tests pin Normal-NC AttrIdx2.

## Measurement boundary

The virtio-GPU scanout is PMM-backed RAM and deliberately remains write-back;
changing it to WC would create conflicting aliases and would not match its
memory ownership. B1875 subsequently added the first firmware/MMIO scanout and
measured its driver-owned WC policy against a temporary UC control: 0.27 s
versus 3.10 s for 125 MiB of full-frame writes (11.5x elapsed). The complete
method and results are retained in `scratch/simplefb-performance-20260806.md`.
