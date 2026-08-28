# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-x86_64.log
boot totals: 1367309 syscalls, 6938 ms on CPU, 5074 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| newfstatat | 20,150 | 788 | 26x | ###### | SEVERE |
| recvfrom | 15,201 | 776 | 20x | ##### | BAD |
| munmap | 24,398 | 1,382 | 18x | #### | BAD |
| write fault, page absent | 15,844 | 1,227 | 13x | ### | BAD |
| recvmsg | 8,759 | 776 | 11x | ### | BAD |
| read | 5,316 | 518 | 10x | ## | BAD |
| openat | 9,188 | 994 | 9x | ## | BAD |
| mprotect | 9,193 | 1,180 | 8x | ## | BAD |
| close | 4,241 | 628 | 7x | ## | BAD |
| mmap | 6,246 | 1,382 | 5x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 2,094,931 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 368 | 699.7 us |
| write | 8,027 | 2,807 | 349.8 us |
| other | 2 | 0 | 18.7 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
