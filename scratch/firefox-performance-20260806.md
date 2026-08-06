# Firefox performance measurements — 2026-08-06

Stable comparison record for B1871. Both profiles used a clean release x86_64
build under KVM with one vCPU and no `debug-*` features. The harness observed
the graphical Wayland scanout through QMP; UART was control/diagnostic only.
Sampling used 350 non-stopping QMP `info registers` snapshots: 200 during the
valid page load and 150 during the invalid-host load.

`smoke::elf::run_as_task` is the boot task's `sti; hlt` idle anchor. A higher
percentage there means the vCPU had less kernel/userspace work to do.

## Workload constants

- Valid page: `https://one.one.one.one`
- Negative lookup: `http://oxide-no-such-host.invalid`
- Browser: Fedora image `/usr/lib64/firefox`, native Wayland
- Settling delay after GNOME readiness: 30 seconds
- Syscall control: three runs of `dd bs=1 count=200000` through `/dev/zero` to
  `/dev/null` (400,000 read/write syscalls per run)

## Before intrusive reclaim links

Raw profile: `/tmp/oxide-firefox-profile-919482.txt` at measurement time.

| Phase | Idle | User | PMM final-free LRU scan | kalloc region scan | tick yield | park yield |
|---|---:|---:|---:|---:|---:|---:|
| all (350) | 40.29% | 12.57% | 8.57% | 9.14% | 6.29% | 6.29% |
| valid (200) | 27.50% | 16.00% | 3.50% | 13.00% | 11.00% | 5.00% |
| invalid (150) | 57.33% | 8.00% | 15.33% | 4.00% | 0% | 8.00% |

Other all-phase samples: `rdtsc` 3.43%, virtio-blk completion 2.57%,
`counter_ns` 1.71%, syscall entry 0.57%.

## After intrusive reclaim links

Branch state: `B1871-firefox-resolver-lockup`, based on `dd45a1bee`, with the
uncommitted O(1) PMM reclaim-list conversion. Raw profile:
`/tmp/oxide-firefox-profile-924764.txt` at measurement time.

| Phase | Idle | User | PMM final-free LRU scan | kalloc region scan | tick yield | park yield |
|---|---:|---:|---:|---:|---:|---:|
| all (350) | 49.14% | 11.14% | **0%** | 10.29% | 5.43% | 4.29% |
| valid (200) | 26.00% | 14.00% | **0%** | 15.00% | 9.50% | 5.50% |
| invalid (150) | 80.00% | 7.33% | **0%** | 4.00% | 0% | 2.67% |

Other all-phase samples: virtio-blk completion 4.57%, `rdtsc` 4.29%,
`counter_ns` 3.14%. No syscall-entry sample was observed.

Settled pre-Firefox load was `3.12 0.85 0.28` on one vCPU. CPU leaders were
fwupd 13.2%, GNOME Shell 9.6%, systemd 4.4%, ibus-extension-gtk3 3.7%, and
GNOME Software 2.4%.

The syscall control remained Linux-class:

| Run | Real | User | Kernel |
|---|---:|---:|---:|
| 1 | 0.091 s | 0.022 s | 0.064 s |
| 2 | 0.079 s | 0.021 s | 0.057 s |
| 3 | 0.081 s | 0.022 s | 0.058 s |

The graphical framebuffer changed in both browser phases and Firefox remained
alive with its content processes. This run independently reproduced the
resolver defect: the baseline resolve1 D-Bus Ping and final negative-lookup
health check each timed out after 20 seconds while `systemd-resolved` remained
alive/sleeping with status `Processing requests...`.

## Interpretation and next comparison

The PMM scan disappeared completely and all-phase idle increased by 8.85
percentage points. The next measured kernel hotspot is
`kalloc::holes::HoleList::owns_range`: it linearly walks every separately
registered 1 MiB heap-growth region while validating ordinary allocator
operations. The next profile must keep this exact workload and sample counts;
success means that symbol disappears or materially falls without losing the
allocator's ownership/corruption checks.

## After balanced kalloc region index

Raw profile: `/tmp/oxide-firefox-profile-926932.txt` at measurement time.
This release run passed the complete graphical Firefox, valid-DNS,
invalid-DNS, and resolver-health harness.

| Phase | Idle anchor | User | kalloc region lookup | `rdtsc` | `counter_ns` | block completion wait | tick yield | park yield |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| all (350) | 7.71% | 23.43% | **0.57%** | 20.00% | 8.00% | 11.43% | 12.00% | 4.86% |
| valid (200) | 2.00% | 32.50% | **1.00%** | 13.00% | 5.50% | 10.00% | 19.50% | 0.50% |
| invalid (150) | 15.33% | 11.33% | **0%** | 29.33% | 11.33% | 13.33% | 2.00% | 10.67% |

Settled load fell from 3.12 to 2.15. The syscall control was 0.088, 0.078,
and 0.077 seconds real, with 0.056–0.061 seconds kernel time. The former
allocator hotspot fell from 10.29% overall / 15.00% valid-load to 0.57% /
1.00% while preserving every ownership check.

This exposed the next cluster: synchronous virtio-block completion waited by
polling up to 200,000 times, calling `monotonic_ns()` (`rdtsc` plus
`counter_ns`) on each iteration. Combined, those leaf samples accounted for
39.43% overall and 28.50% of valid-load samples. Linux blocks on the request
completion rather than spending a latency-sized fixed spin budget.

## After bounded IRQ bridge plus deadline-backed block sleep

Raw profile: `/tmp/oxide-firefox-profile-945478.txt` at measurement time.
This release run also passed the complete graphical Firefox, valid-DNS,
invalid-DNS, and resolver-health harness.

The first attempt to park immediately never reached the graphical session and
is deliberately excluded from performance results. Oxide currently enters the
synchronous path with IRQs masked; on one vCPU it needs a short local-IRQ
delivery window before parking. The accepted implementation probes only the
used-ring index at most 64 times with IRQs enabled (down from 200,000), performs
no clock conversion inside that loop, then uses the register/recheck wait with
a scheduler-armed five-second deadline.

| Phase | `tick_yield` halt | Idle anchor | Idle-equivalent total | User | kalloc lookup | PMM unlink | `rdtsc` | `counter_ns` | block completion wait |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| all (350) | 83.14% | 3.14% | **86.28%** | 7.14% | 0% | 0% | 0% | 0% | 0% |
| valid (200) | 77.50% | 5.50% | **83.00%** | 10.50% | 0% | 0% | 0% | 0% | 0% |
| invalid (150) | 90.67% | 0% | **90.67%** | 2.67% | 0% | 0% | 0% | 0% | 0% |

`tick_yield` ends in `sti; hlt; cli`; QMP snapshots leave the RIP in that
function while the vCPU is halted. Its dominant percentage is therefore idle
residency, not active scheduler CPU cost. No former memory-manager or block
polling hotspot remained in 350 samples.

Settled pre-Firefox load was `0.98 0.27 0.09`, versus 2.15 after only the
allocator fixes and 3.12 before them. GNOME Shell reported 5.8% CPU versus
8.4% and 9.6%. The syscall control's kernel time remained 0.056–0.057 seconds;
real times were 0.194, 0.121, and 0.079 seconds because the first two runs were
descheduled, not because syscall execution regressed.
