# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-x86_64-lazy-xattr.log
boot totals: 1368308 syscalls, 6048 ms on CPU, 4420 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| munmap | 24,210 | 1,382 | 18x | #### | BAD |
| recvfrom | 12,879 | 776 | 17x | #### | BAD |
| newfstatat | 11,500 | 788 | 15x | #### | BAD |
| recvmsg | 8,713 | 776 | 11x | ### | BAD |
| write fault, page absent | 12,114 | 1,227 | 10x | ## | BAD |
| read | 4,861 | 518 | 9x | ## | BAD |
| openat | 7,828 | 994 | 8x | ## | BAD |
| mprotect | 8,220 | 1,180 | 7x | ## | BAD |
| close | 4,013 | 628 | 6x | ## | BAD |
| mmap | 5,780 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,039,328 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 274 | 521.7 us |
| write | 8,255 | 2,987 | 361.9 us |
| other | 2 | 0 | 26.5 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
