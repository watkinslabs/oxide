# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2812/target/perf-report-x86.log
boot totals: 1365939 syscalls, 6823 ms on CPU, 4995 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| recvfrom | 20,806 | 776 | 27x | ###### | SEVERE |
| newfstatat | 20,627 | 788 | 26x | ###### | SEVERE |
| munmap | 29,733 | 1,382 | 22x | ##### | SEVERE |
| mprotect | 18,043 | 1,180 | 15x | #### | BAD |
| write fault, page absent | 12,577 | 1,227 | 10x | ## | BAD |
| recvmsg | 7,768 | 776 | 10x | ## | BAD |
| read | 4,892 | 518 | 9x | ## | BAD |
| openat | 9,226 | 994 | 9x | ## | BAD |
| mmap | 9,721 | 1,382 | 7x | ## | BAD |
| close | 3,412 | 628 | 5x | # | BAD |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,276,459 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 301 | 572.9 us |
| write | 8,016 | 2,174 | 271.3 us |
| other | 2 | 0 | 9.9 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
