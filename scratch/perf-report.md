# Syscall and fault cost vs the host Linux kernel

oxide: target/perf-report-e4-08-inode-writer-hold.log
boot totals: 1368001 syscalls, 6244 ms on CPU, 4565 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 18,710 | 788 | 24x | ###### | SEVERE |
| munmap | 23,925 | 1,382 | 17x | #### | BAD |
| recvfrom | 12,634 | 776 | 16x | #### | BAD |
| recvmsg | 7,937 | 776 | 10x | ## | BAD |
| write fault, page absent | 12,265 | 1,227 | 10x | ## | BAD |
| read | 5,012 | 518 | 10x | ## | BAD |
| openat | 8,188 | 994 | 8x | ## | BAD |
| mprotect | 8,457 | 1,180 | 7x | ## | BAD |
| close | 4,018 | 628 | 6x | ## | BAD |
| mmap | 6,000 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,055,711 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 252 | 480.9 us |
| write | 7,999 | 2,682 | 335.4 us |
| other | 2 | 0 | 29.3 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
