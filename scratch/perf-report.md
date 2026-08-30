# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel/target/perf-report-x86_64.log
boot totals: 1369009 syscalls, 5733 ms on CPU, 4187 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| recvfrom | 11,721 | 776 | 15x | #### | BAD |
| munmap | 20,803 | 1,382 | 15x | #### | BAD |
| newfstatat | 11,833 | 788 | 15x | #### | BAD |
| recvmsg | 11,570 | 776 | 15x | #### | BAD |
| read | 4,639 | 518 | 9x | ## | BAD |
| write fault, page absent | 10,903 | 1,227 | 9x | ## | BAD |
| openat | 7,215 | 994 | 7x | ## | BAD |
| close | 4,002 | 628 | 6x | ## | BAD |
| mprotect | 7,270 | 1,180 | 6x | # | BAD |
| mmap | 5,415 | 1,382 | 4x | # | slow |

## Measured, not compared

| operation | oxide ns | why no ratio |
|---|---:|---|
| writev | 1,871,295 | console output; fbcon scrolls the framebuffer, host baseline writes to /dev/null |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 526 | 284 | 541.5 us |
| write | 8,020 | 3,539 | 441.4 us |
| flush | 48 | 169 | 3540.1 us |
| other | 2 | 0 | 20.3 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.

Run-to-run variance on the oxide side is large — the boot does not make the same mix of calls twice, and the socket rows swing by tens of percent between runs. A change is only demonstrated here when it moves a row by more than about half, or moves it across a verdict band. Anything smaller needs repeated runs or a hosted microbenchmark.
