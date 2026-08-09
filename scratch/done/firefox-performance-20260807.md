# Firefox performance measurement — 2026-08-07

Clean release, KVM, x86_64, one vCPU. Command:

`OXIDE_FIREFOX_PROFILE=1 tools/guest-firefox-check.py 600`

## Results

| Probe | Result | Interpretation |
|---|---:|---|
| `dd if=/dev/zero of=/dev/null bs=1 count=200000` | 0.093 s, 0.082 s, 0.084 s | Each run makes 400,000 read/write syscalls: 0.233, 0.205, 0.210 us/syscall wall time. |
| Kernel time in the same runs | 0.061 s, 0.060 s, 0.062 s | 0.150--0.155 us/syscall in kernel. |
| HTTPS control (`one.one.one.one`) | 33.915 ms transfer, 64 ms shell wall | DNS, TCP, TLS and HTTP/1.1 completed. |
| Firefox valid page | Resolver lookup and Firefox health command returned 0. | Browser launch completed. |
| Firefox invalid DNS tab | `getent` returned the expected NXDOMAIN status; Firefox and `systemd-resolved` health command returned 0. | No lockup or resolver loss. |

The former 2.06 us/syscall number is obsolete. The current result is within the
rough 0.2 us Linux reference for this deliberately tiny I/O probe; it is not
evidence for another syscall-exit fast-path change.

## Sampling caveat

Raw QMP samples: `/tmp/oxide-firefox-profile-3593807.txt`; UART evidence:
`/tmp/oxide-firefox-uart-3593807.log`; build/QEMU output:
`/tmp/oxide-firefox-qemu-3593807.log`.

The sampler captured instruction-pointer snapshots rather than scheduled CPU
samples. During the invalid-DNS window 79/150 kernel-labelled snapshots resolve
to `smoke::elf::run_as_task`, which is not a credible Firefox execution hotspot.
Treat that distribution as a liveness record only, not a basis for an optimizer
change. A future performance investigation needs task-attributed sampling before
claiming a CPU bottleneck.
