# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-x86_64.log
boot totals: 1369358 syscalls, 5633 ms on CPU, 4114 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| recvfrom | 12,325 | 776 | 16x | #### | BAD |
| newfstatat | 12,173 | 788 | 15x | #### | BAD |
| munmap | 20,734 | 1,382 | 15x | #### | BAD |
| recvmsg | 8,302 | 776 | 11x | ### | BAD |
| write fault, page absent | 12,111 | 1,227 | 10x | ## | BAD |
| read | 4,469 | 518 | 9x | ## | BAD |
| openat | 7,189 | 994 | 7x | ## | BAD |
| mprotect | 7,396 | 1,180 | 6x | ## | BAD |
| close | 3,805 | 628 | 6x | # | BAD |
| mmap | 5,455 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,875,421 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 255 | 485.9 us |
| write | 8,120 | 3,156 | 388.8 us |
| flush | 55 | 178 | 3252.8 us |
| other | 2 | 0 | 30.3 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
