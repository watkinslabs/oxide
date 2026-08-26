# Syscall and fault cost vs the host Linux kernel

oxide: /home/nd/oxide/kernel-B2674/target/perf-report-x86_64.log
boot totals: 1363252 syscalls, 11199 ms on CPU, 8214 ns average

| operation | oxide ns | linux ns | ratio | | verdict |
|---|---:|---:|---:|---|---|
| writev | 1,308,491 | 495 | 2643x | ######################## | SEVERE |
| recvmsg | 67,758 | 776 | 87x | ##################### | SEVERE |
| sendmmsg | 62,705 | 776 | 81x | ################### | SEVERE |
| sendmsg | 48,325 | 776 | 62x | ############### | SEVERE |
| munmap | 83,075 | 1,382 | 60x | ############## | SEVERE |
| newfstatat | 27,286 | 788 | 35x | ######## | SEVERE |
| recvfrom | 26,675 | 776 | 34x | ######## | SEVERE |
| read | 8,914 | 518 | 17x | #### | BAD |
| mprotect | 16,362 | 1,180 | 14x | ### | BAD |
| close | 7,918 | 628 | 13x | ### | BAD |
| openat | 11,659 | 994 | 12x | ### | BAD |
| mmap | 12,857 | 1,382 | 9x | ## | BAD |
| write fault, page absent | 11,385 | 1,227 | 9x | ## | BAD |

## Block device

| op | count | total ms | avg |
|---|---:|---:|---:|
| read | 16,495 | 3,245 | 196.8 us |
| write | 402,274 | 30,818 | 76.6 us |
| flush | 2,975 | 23,961 | 8054.2 us |
| other | 2 | 0 | 30.3 us |

Both sides are measured. The host figure is a tight loop over one shape of the call; the oxide figure is the average over every such call a real desktop boot made. Read a ratio as an order of magnitude, not a score.
