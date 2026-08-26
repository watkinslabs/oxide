# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2699/target/perf-report-x86_64.log
boot totals: 1170786 syscalls, 7318 ms on CPU, 6250 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| munmap | 71,407 | 1,382 | 52x | ############ | SEVERE |
| sendmsg | 28,235 | 776 | 36x | ######### | SEVERE |
| newfstatat | 22,519 | 788 | 29x | ####### | SEVERE |
| recvfrom | 19,691 | 776 | 25x | ###### | SEVERE |
| recvmsg | 10,888 | 776 | 14x | ### | BAD |
| write fault, page absent | 16,639 | 1,227 | 14x | ### | BAD |
| read | 5,381 | 518 | 10x | ## | BAD |
| openat | 9,855 | 994 | 10x | ## | BAD |
| mmap | 10,365 | 1,382 | 8x | ## | BAD |
| close | 4,471 | 628 | 7x | ## | BAD |
| mprotect | 7,635 | 1,180 | 6x | ## | BAD |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,877,782 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 338 | 643.9 us |
| write | 7,745 | 2,967 | 383.2 us |
| flush | 22 | 182 | 8307.9 us |
| other | 2 | 0 | 32.0 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
