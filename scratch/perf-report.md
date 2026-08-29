# Syscall and fault cost vs the host Linux kernel

oxide: target/perf-report-e4-08-linear-fast-match-repeat.log
boot totals: 1367794 syscalls, 6863 ms on CPU, 5017 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 18,188 | 788 | 23x | ###### | SEVERE |
| recvfrom | 15,880 | 776 | 20x | ##### | SEVERE |
| munmap | 24,873 | 1,382 | 18x | #### | BAD |
| write fault, page absent | 18,025 | 1,227 | 15x | #### | BAD |
| recvmsg | 11,342 | 776 | 15x | #### | BAD |
| read | 6,082 | 518 | 12x | ### | BAD |
| openat | 8,286 | 994 | 8x | ## | BAD |
| close | 4,596 | 628 | 7x | ## | BAD |
| mprotect | 8,612 | 1,180 | 7x | ## | BAD |
| mmap | 5,974 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,163,548 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 536 | 1020.6 us |
| write | 8,053 | 2,872 | 356.7 us |
| other | 2 | 0 | 16.5 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
