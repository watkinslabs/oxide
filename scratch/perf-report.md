# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2681/target/perf-report-x86_64.log
boot totals: 1365214 syscalls, 7971 ms on CPU, 5839 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| munmap | 91,111 | 1,382 | 66x | ################ | SEVERE |
| sendmmsg | 48,484 | 776 | 62x | ############### | SEVERE |
| sendmsg | 39,403 | 776 | 51x | ############ | SEVERE |
| newfstatat | 22,555 | 788 | 29x | ####### | SEVERE |
| recvfrom | 17,452 | 776 | 22x | ##### | SEVERE |
| write fault, page absent | 19,157 | 1,227 | 16x | #### | BAD |
| mprotect | 15,950 | 1,180 | 14x | ### | BAD |
| recvmsg | 10,035 | 776 | 13x | ### | BAD |
| openat | 10,487 | 994 | 11x | ### | BAD |
| read | 5,196 | 518 | 10x | ## | BAD |
| mmap | 11,635 | 1,382 | 8x | ## | BAD |
| close | 3,120 | 628 | 5x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,280,219 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 18,831 | 7,948 | 422.1 us |
| write | 8,064 | 1,717 | 213.0 us |
| flush | 25 | 183 | 7338.6 us |
| other | 2 | 0 | 25.6 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
