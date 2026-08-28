# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2812/target/perf-report-x86.log
boot totals: 1366783 syscalls, 7411 ms on CPU, 5422 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| mprotect | 66,750 | 1,180 | 57x | ############## | SEVERE |
| newfstatat | 21,018 | 788 | 27x | ###### | SEVERE |
| recvfrom | 14,785 | 776 | 19x | ##### | BAD |
| munmap | 23,562 | 1,382 | 17x | #### | BAD |
| openat | 9,994 | 994 | 10x | ## | BAD |
| write fault, page absent | 12,104 | 1,227 | 10x | ## | BAD |
| recvmsg | 7,517 | 776 | 10x | ## | BAD |
| read | 4,475 | 518 | 9x | ## | BAD |
| close | 4,309 | 628 | 7x | ## | BAD |
| mmap | 9,297 | 1,382 | 7x | ## | BAD |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,327,177 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 344 | 655.4 us |
| write | 7,937 | 2,561 | 322.7 us |
| other | 2 | 0 | 9.4 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.

## Regressions against the ratio baseline

| operation | was | now |
|---|---:|---:|
| mprotect | 15x | 57x |
