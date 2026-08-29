# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-e4-08-no-write-inode-reread.log
boot totals: 1367536 syscalls, 6619 ms on CPU, 4840 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 18,734 | 788 | 24x | ###### | SEVERE |
| recvfrom | 15,737 | 776 | 20x | ##### | SEVERE |
| munmap | 25,002 | 1,382 | 18x | #### | BAD |
| write fault, page absent | 15,818 | 1,227 | 13x | ### | BAD |
| recvmsg | 9,993 | 776 | 13x | ### | BAD |
| read | 5,316 | 518 | 10x | ## | BAD |
| openat | 8,274 | 994 | 8x | ## | BAD |
| mprotect | 8,604 | 1,180 | 7x | ## | BAD |
| close | 4,095 | 628 | 7x | ## | BAD |
| mmap | 6,009 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,049,560 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 448 | 851.9 us |
| write | 8,165 | 2,694 | 330.1 us |
| other | 2 | 0 | 29.9 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
